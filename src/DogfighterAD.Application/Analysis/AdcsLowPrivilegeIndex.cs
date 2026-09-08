using DogfighterAD.Domain.Analysis;
using DogfighterAD.Domain.Findings;
using DogfighterAD.Domain.Snapshots;

namespace DogfighterAD.Application.Analysis;

/// <summary>
/// Snapshot-only proof that a SID names a broad low-privilege principal, or a group that contains at
/// least one enabled non-privileged user through the collected nested membership graph. Negative
/// answers are usable only when ScopeComplete is true.
/// </summary>
internal sealed class AdcsLowPrivilegeIndex
{
    private static readonly HashSet<string> BroadWellKnownSids = new(StringComparer.OrdinalIgnoreCase)
    {
        "S-1-1-0",      // Everyone
        "S-1-5-11",     // Authenticated Users
        "S-1-5-32-545"  // Builtin Users
    };

    private readonly Dictionary<string, ProofNode> lowPrivilegeBySid =
        new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<AdObjectId, ProofNode> reachable = [];
    private readonly Dictionary<string, IReadOnlyList<Evidence>> domainSidEvidence =
        new(StringComparer.OrdinalIgnoreCase);

    public AdcsLowPrivilegeIndex(
        AdSnapshot snapshot,
        ObservationIndex facts,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(snapshot);
        ArgumentNullException.ThrowIfNull(facts);

        ScopeComplete = RequiredCoverageComplete(snapshot);
        var privileged = new PrivilegedMembershipIndex(snapshot, facts, cancellationToken);
        if (!privileged.ScopeComplete)
        {
            ScopeComplete = false;
        }

        var objects = AnalysisSubjects.Objects(snapshot.Content).ToDictionary(item => item.Id);
        var groupSids = new Dictionary<AdObjectId, FactRead<string>>();

        foreach (var domain in snapshot.Content.Domains)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var sid = facts.Text(
                CollectionCapabilities.DirectoryDomains,
                $"ad-object:{domain.Id}",
                "domain.objectSid",
                FactValueKind.Sid);
            if (!sid.Known || string.IsNullOrWhiteSpace(sid.Value))
            {
                ScopeComplete = false;
                continue;
            }

            domainSidEvidence.TryAdd(sid.Value, sid.Evidence);
        }
        if (domainSidEvidence.Count == 0)
        {
            ScopeComplete = false;
        }

        foreach (var group in snapshot.Content.Groups)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var sid = facts.Text(
                CollectionCapabilities.DirectoryGroups,
                $"ad-object:{group.Id}",
                "object.objectSid",
                FactValueKind.Sid);
            groupSids[group.Id] = sid;
            if (!sid.Known || string.IsNullOrWhiteSpace(sid.Value))
            {
                ScopeComplete = false;
            }
        }

        var parents = BuildParentEdges(snapshot, facts, objects, groupSids, cancellationToken);
        if (!parents.Complete)
        {
            ScopeComplete = false;
        }

        var queue = new Queue<AdObjectId>();
        foreach (var user in snapshot.Content.Users.OrderBy(item => item.Id.Value))
        {
            cancellationToken.ThrowIfCancellationRequested();
            var subject = $"ad-object:{user.Id}";
            var sid = facts.Text(
                CollectionCapabilities.DirectoryUsers,
                subject,
                "object.objectSid",
                FactValueKind.Sid);
            var uac = facts.Integer(
                CollectionCapabilities.DirectoryUsers,
                subject,
                "user.userAccountControl");

            if (!sid.Known || string.IsNullOrWhiteSpace(sid.Value) || !uac.Known)
            {
                ScopeComplete = false;
                continue;
            }

            if ((uac.Value & 0x2) != 0)
            {
                continue;
            }

            if (privileged.TryProve(user.Id, out _))
            {
                continue;
            }

            if (!privileged.ScopeComplete)
            {
                ScopeComplete = false;
                continue;
            }

            var proof = new ProofNode(
                Parent: null,
                Evidence: sid.Evidence.Concat(uac.Evidence).ToArray(),
                Depth: 0);
            reachable.TryAdd(user.Id, proof);
            lowPrivilegeBySid.TryAdd(sid.Value, proof);
            queue.Enqueue(user.Id);
        }

        while (queue.TryDequeue(out var memberId))
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!parents.Edges.TryGetValue(memberId, out var parentGroups))
            {
                continue;
            }

            var memberProof = reachable[memberId];
            if (memberProof.Depth >= 64)
            {
                ScopeComplete = false;
                continue;
            }

            foreach (var edge in parentGroups.OrderBy(item => item.GroupId.Value))
            {
                if (!reachable.TryAdd(
                        edge.GroupId,
                        new ProofNode(memberProof, edge.Evidence, memberProof.Depth + 1)))
                {
                    continue;
                }

                if (groupSids.TryGetValue(edge.GroupId, out var groupSid) &&
                    groupSid.Known &&
                    !string.IsNullOrWhiteSpace(groupSid.Value))
                {
                    lowPrivilegeBySid.TryAdd(groupSid.Value, reachable[edge.GroupId]);
                }
                else
                {
                    ScopeComplete = false;
                }

                queue.Enqueue(edge.GroupId);
            }
        }
    }

    public bool ScopeComplete { get; private set; }

    public bool TryProveLowPrivilegeTrustee(
        string? sid,
        out IReadOnlyList<Evidence> evidence)
    {
        evidence = [];
        if (string.IsNullOrWhiteSpace(sid))
        {
            return false;
        }

        if (BroadWellKnownSids.Contains(sid))
        {
            return true;
        }

        foreach (var domain in domainSidEvidence)
        {
            if (StringComparer.OrdinalIgnoreCase.Equals(sid, domain.Key + "-513"))
            {
                evidence = domain.Value;
                return true;
            }
        }

        if (!lowPrivilegeBySid.TryGetValue(sid, out var proof))
        {
            return false;
        }

        var result = new List<Evidence>();
        for (ProofNode? current = proof; current is not null; current = current.Parent)
        {
            result.AddRange(current.Evidence);
        }

        evidence = result
            .DistinctBy(item => item.FactId, StringComparer.Ordinal)
            .OrderBy(item => item.FactId, StringComparer.Ordinal)
            .ToArray();
        return true;
    }

    private static bool RequiredCoverageComplete(AdSnapshot snapshot)
    {
        var required = new[]
        {
            CollectionCapabilities.DirectoryUsers,
            CollectionCapabilities.DirectoryGroups,
            CollectionCapabilities.DirectoryMemberships,
            CollectionCapabilities.DirectoryDomains
        };

        return required.All(capability => snapshot.Coverage.Any(item =>
            item.CapabilityId == capability && item.Status == CapabilityStatus.Complete));
    }

    private static ParentEdgeResult BuildParentEdges(
        AdSnapshot snapshot,
        ObservationIndex facts,
        IReadOnlyDictionary<AdObjectId, AdDirectoryObject> objects,
        IReadOnlyDictionary<AdObjectId, FactRead<string>> groupSids,
        CancellationToken cancellationToken)
    {
        var result = new Dictionary<AdObjectId, List<ParentEdge>>();
        var complete = true;

        foreach (var edge in snapshot.Content.GroupMemberships
                     .OrderBy(item => item.GroupId.Value)
                     .ThenBy(item => item.MemberId.Value)
                     .ThenBy(item => item.Source))
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!objects.TryGetValue(edge.MemberId, out var member) ||
                !groupSids.TryGetValue(edge.GroupId, out var groupSid) ||
                !groupSid.Known)
            {
                complete = false;
                continue;
            }

            IReadOnlyList<Evidence> evidence;
            if (edge.Source == MembershipSource.Explicit)
            {
                var values = facts.Values(
                    CollectionCapabilities.DirectoryMemberships,
                    $"ad-object:{edge.GroupId}",
                    "group.member",
                    FactValueKind.DistinguishedName);
                if (!values.Known ||
                    !values.Value.Contains(member.DistinguishedName, StringComparer.OrdinalIgnoreCase))
                {
                    complete = false;
                    continue;
                }

                evidence = values.Evidence
                    .Where(item => StringComparer.OrdinalIgnoreCase.Equals(
                        item.Value,
                        member.DistinguishedName))
                    .ToArray();
            }
            else
            {
                var rid = facts.Integer(
                    CollectionCapabilities.DirectoryMemberships,
                    $"ad-object:{edge.MemberId}",
                    "principal.primaryGroupId");
                var memberCapability = member switch
                {
                    AdUser => CollectionCapabilities.DirectoryUsers,
                    AdComputer => CollectionCapabilities.DirectoryComputers,
                    _ => CollectionCapabilities.DirectoryMemberships
                };
                var memberSidPath = member is AdUser or AdComputer
                    ? "object.objectSid"
                    : "support.objectSid";
                var memberSid = facts.Text(
                    memberCapability,
                    $"ad-object:{edge.MemberId}",
                    memberSidPath,
                    FactValueKind.Sid);

                if (!rid.Known || !memberSid.Known || string.IsNullOrWhiteSpace(memberSid.Value))
                {
                    complete = false;
                    continue;
                }

                var cut = memberSid.Value.LastIndexOf('-');
                if (cut <= 0 ||
                    !StringComparer.OrdinalIgnoreCase.Equals(
                        groupSid.Value,
                        memberSid.Value[..cut] + "-" + rid.Value.ToString(System.Globalization.CultureInfo.InvariantCulture)))
                {
                    complete = false;
                    continue;
                }

                evidence = rid.Evidence
                    .Concat(memberSid.Evidence)
                    .Concat(groupSid.Evidence)
                    .ToArray();
            }

            if (!result.TryGetValue(edge.MemberId, out var parents))
            {
                result[edge.MemberId] = parents = [];
            }
            parents.Add(new ParentEdge(edge.GroupId, evidence));
        }

        return new ParentEdgeResult(result, complete);
    }

    private sealed record ParentEdge(
        AdObjectId GroupId,
        IReadOnlyList<Evidence> Evidence);

    private sealed record ParentEdgeResult(
        IReadOnlyDictionary<AdObjectId, List<ParentEdge>> Edges,
        bool Complete);

    private sealed record ProofNode(
        ProofNode? Parent,
        IReadOnlyList<Evidence> Evidence,
        int Depth);
}
