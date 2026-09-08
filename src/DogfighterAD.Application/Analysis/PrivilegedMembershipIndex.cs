using System.Globalization;
using DogfighterAD.Domain.Analysis;
using DogfighterAD.Domain.Findings;
using DogfighterAD.Domain.Snapshots;

namespace DogfighterAD.Application.Analysis;

/// <summary>Cycle-safe, snapshot-only membership reachability. Never treats adminCount as membership.</summary>
internal sealed class PrivilegedMembershipIndex
{
    private readonly Dictionary<AdObjectId, ProofNode> _reachable = [];
    public bool ScopeComplete { get; private set; } = true;
    private static readonly HashSet<string> BuiltinRoots = new(StringComparer.OrdinalIgnoreCase)
    { "S-1-5-32-544", "S-1-5-32-548", "S-1-5-32-549", "S-1-5-32-550", "S-1-5-32-551" };
    private static readonly int[] DomainRootRids = [512, 518, 519, 526, 527];

    public PrivilegedMembershipIndex(AdSnapshot snapshot, ObservationIndex facts, CancellationToken token)
    {
        var objects = AnalysisSubjects.Objects(snapshot.Content).ToDictionary(x => x.Id);
        var domainSidEvidence = new Dictionary<string, IReadOnlyList<Evidence>>(StringComparer.OrdinalIgnoreCase);
        foreach (var domain in snapshot.Content.Domains)
        {
            var value = facts.Text(CollectionCapabilities.DirectoryDomains, $"ad-object:{domain.Id}", "domain.objectSid", FactValueKind.Sid);
            if (!value.Known || string.IsNullOrWhiteSpace(value.Value)) { ScopeComplete = false; continue; }
            domainSidEvidence.TryAdd(value.Value, value.Evidence);
        }
        if (domainSidEvidence.Count == 0) ScopeComplete = false;
        var groupSids = new Dictionary<AdObjectId, FactRead<string>>();
        var queue = new Queue<AdObjectId>();
        foreach (var group in snapshot.Content.Groups.OrderBy(g => g.Id.Value))
        {
            token.ThrowIfCancellationRequested();
            var sid = facts.Text(CollectionCapabilities.DirectoryGroups, $"ad-object:{group.Id}", "object.objectSid", FactValueKind.Sid);
            groupSids[group.Id] = sid;
            if (!sid.Known || string.IsNullOrWhiteSpace(sid.Value)) { ScopeComplete = false; continue; }
            var rootEvidence = sid.Evidence.ToList();
            var root = BuiltinRoots.Contains(sid.Value);
            foreach (var domain in domainSidEvidence)
                if (DomainRootRids.Any(rid => StringComparer.OrdinalIgnoreCase.Equals(sid.Value, domain.Key + "-" + rid.ToString(CultureInfo.InvariantCulture))))
                { root = true; rootEvidence.AddRange(domain.Value); }
            if (root)
            {
                _reachable.TryAdd(group.Id, new(null, rootEvidence, 0));
                queue.Enqueue(group.Id);
            }
        }
        foreach (var capability in new[] { CollectionCapabilities.DirectoryGroups, CollectionCapabilities.DirectoryMemberships, CollectionCapabilities.DirectoryDomains })
            if (!snapshot.Coverage.Any(c => c.CapabilityId == capability && c.Status == CapabilityStatus.Complete)) ScopeComplete = false;

        var edges = new Dictionary<AdObjectId, List<(AdObjectId Member, IReadOnlyList<Evidence> Evidence)>>();
        foreach (var edge in snapshot.Content.GroupMemberships.OrderBy(x => x.GroupId.Value).ThenBy(x => x.MemberId.Value).ThenBy(x => x.Source))
        {
            token.ThrowIfCancellationRequested();
            if (!objects.TryGetValue(edge.MemberId, out var member) || !groupSids.TryGetValue(edge.GroupId, out var groupSid))
            { ScopeComplete = false; continue; }
            List<Evidence> proof = [];
            if (edge.Source == MembershipSource.Explicit)
            {
                var values = facts.Values(CollectionCapabilities.DirectoryMemberships, $"ad-object:{edge.GroupId}", "group.member", FactValueKind.DistinguishedName);
                if (!values.Known || !values.Value.Contains(member.DistinguishedName, StringComparer.OrdinalIgnoreCase))
                { ScopeComplete = false; continue; }
                proof.AddRange(values.Evidence.Where(e => StringComparer.OrdinalIgnoreCase.Equals(e.Value, member.DistinguishedName)));
            }
            else
            {
                var rid = facts.Integer(CollectionCapabilities.DirectoryMemberships, $"ad-object:{edge.MemberId}", "principal.primaryGroupId");
                var cap = member is AdUser ? CollectionCapabilities.DirectoryUsers : member is AdComputer ? CollectionCapabilities.DirectoryComputers : CollectionCapabilities.DirectoryMemberships;
                var sidPath = member is AdUser or AdComputer ? "object.objectSid" : "support.objectSid";
                var sid = facts.Text(cap, $"ad-object:{edge.MemberId}", sidPath, FactValueKind.Sid);
                if (!rid.Known || rid.Value < 0 || !sid.Known || !groupSid.Known || string.IsNullOrWhiteSpace(sid.Value))
                { ScopeComplete = false; continue; }
                var cut = sid.Value.LastIndexOf('-');
                if (cut <= 0 || !StringComparer.OrdinalIgnoreCase.Equals(groupSid.Value,
                        sid.Value[..cut] + "-" + rid.Value.ToString(CultureInfo.InvariantCulture)))
                { ScopeComplete = false; continue; }
                proof.AddRange(rid.Evidence); proof.AddRange(sid.Evidence); proof.AddRange(groupSid.Evidence);
            }
            if (!edges.TryGetValue(edge.GroupId, out var list)) edges[edge.GroupId] = list = [];
            list.Add((edge.MemberId, proof));
        }
        // A coverage label by itself is not evidence that omitted relationships are absent.
        // Require explicit per-group direct-member enumeration bounds before a negative proof.
        var explicitCounts = snapshot.Content.GroupMemberships.Where(e => e.Source == MembershipSource.Explicit)
            .GroupBy(e => e.GroupId).ToDictionary(g => g.Key, g => g.Count());
        var primaryMembers = snapshot.Content.GroupMemberships.Where(e => e.Source == MembershipSource.PrimaryGroup)
            .Select(e => e.MemberId).ToHashSet();
        foreach (var group in snapshot.Content.Groups)
        {
            token.ThrowIfCancellationRequested();
            var sub = $"ad-object:{group.Id}";
            var complete = facts.Boolean(CollectionCapabilities.DirectoryMemberships, sub, "group.memberReadComplete");
            var count = facts.Integer(CollectionCapabilities.DirectoryMemberships, sub, "group.observedMemberCount");
            var returned = facts.Values(CollectionCapabilities.DirectoryMemberships, sub, "group.member", FactValueKind.DistinguishedName);
            var explicitEdges = explicitCounts.GetValueOrDefault(group.Id);
            if (!complete.Known || !complete.Value || !count.Known || count.Value < 0 || count.Value != explicitEdges ||
                (count.Value > 0 && (!returned.Known || returned.Value.Count != count.Value)) ||
                (count.Value == 0 && returned.Known && returned.Value.Count != 0)) ScopeComplete = false;
        }
        // Primary-group edges must also have explicit operands. Do not silently treat omitted
        // primaryGroupID on an in-scope security principal as the absence of that relationship.
        foreach (var principal in snapshot.Content.Users.Cast<AdDirectoryObject>().Concat(snapshot.Content.Computers))
        {
            var rid = facts.Integer(CollectionCapabilities.DirectoryMemberships, $"ad-object:{principal.Id}", "principal.primaryGroupId");
            if (!rid.Known || rid.Value is < 0 or > uint.MaxValue ||
                !primaryMembers.Contains(principal.Id))
                ScopeComplete = false;
        }
        while (queue.TryDequeue(out var groupId))
        {
            token.ThrowIfCancellationRequested();
            var parent = _reachable[groupId];
            if (!edges.TryGetValue(groupId, out var children)) continue;
            if (parent.Depth >= 64) { ScopeComplete = false; continue; }
            foreach (var edge in children)
                if (_reachable.TryAdd(edge.Member, new(parent, edge.Evidence, parent.Depth + 1)))
                {
                    if (_reachable.Count > 1_000_000) throw new AnalysisLimitException();
                    if (groupSids.ContainsKey(edge.Member)) queue.Enqueue(edge.Member);
                }
        }
    }

    public bool TryProve(AdObjectId id, out IReadOnlyList<Evidence> evidence)
    {
        evidence = [];
        if (!_reachable.TryGetValue(id, out var node)) return false;
        var result = new List<Evidence>();
        for (ProofNode? current = node; current is not null; current = current.Parent) result.AddRange(current.Evidence);
        evidence = result.DistinctBy(e => e.FactId, StringComparer.Ordinal).OrderBy(e => e.FactId, StringComparer.Ordinal).ToArray();
        return true;
    }
    private sealed record ProofNode(ProofNode? Parent, IReadOnlyList<Evidence> Evidence, int Depth);
}
