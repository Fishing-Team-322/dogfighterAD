using DogfighterAD.Application.Contracts;
using DogfighterAD.Domain.Analysis;
using DogfighterAD.Domain.Snapshots;

namespace DogfighterAD.Application.Analysis.Rules;

public enum AclTest { UnrestrictedDacl, GenericAll, GenericWrite, WriteDacl, WriteOwner, ResetPassword, ReplicationRight }
public sealed class AclRule : RuleBase
{
    private readonly AclTest _test;
    public AclRule(RuleMetadata metadata, AclTest test) : base(metadata) => _test = test;
    public override IEnumerable<RuleEvaluation> Evaluate(AdSnapshot snapshot, RuleContext context)
    {
        const string cap = CollectionCapabilities.DirectoryAcls;
        var aces = snapshot.Content.Aces.GroupBy(x => x.TargetObjectId).ToDictionary(g => g.Key, g => g.OrderBy(x => x.AceIndex).ToArray());
        // This is the collector's declared scope, not every possible securable AD object.
        var subjects = snapshot.Content.Domains.Cast<AdDirectoryObject>().Concat(snapshot.Content.Users)
            .Concat(snapshot.Content.Groups).Concat(snapshot.Content.Computers).Concat(snapshot.Content.OrganizationalUnits);
        foreach (var subject in subjects.OrderBy(x => x.Id.Value))
        {
            if (_test == AclTest.ReplicationRight && subject is not AdDomain) continue;
            var descriptor = Check(context, subject);
            var state = descriptor.Text(cap, "securityDescriptor.daclState");
            descriptor.Require(state is "NotPresent" or "Null" or "Empty" or "Present", cap, "securityDescriptor.daclState", "field.invalid-dacl-state");
            if (!descriptor.Known) { yield return descriptor.Unknown(); continue; }
            if (_test == AclTest.UnrestrictedDacl)
            { yield return descriptor.Verdict(state is "Null" or "NotPresent", "Observed DACL state=" + state + ". Null/absent and empty DACLs have different access semantics; no empty DACL is treated as unrestricted."); continue; }
            var complete = descriptor.Boolean(cap, "securityDescriptor.parseComplete");
            var count = descriptor.Integer(cap, "securityDescriptor.aceCount");
            var targetAces = aces.TryGetValue(subject.Id, out var found) ? found : [];
            descriptor.Require(complete && count == targetAces.Length && count >= 0,
                cap, "securityDescriptor.aceCount/parseComplete", "descriptor.incomplete-or-inconsistent");
            if (!descriptor.Known) { yield return descriptor.Unknown(); continue; }
            if (state is "Null" or "NotPresent")
            { yield return descriptor.NotApplicable("Unrestricted descriptor handled by the unrestricted-DACL rule; no Allow ACE is invented."); continue; }
            var emitted = false;
            foreach (var ace in targetAces)
            {
                context.CancellationToken.ThrowIfCancellationRequested();
                var check = Check(context, subject);
                var p = $"securityDescriptor.dacl.ace[{ace.AceIndex}]";
                var access = check.Text(cap, p + ".accessType");
                var flags = check.Integer(cap, p + ".aceFlags");
                check.Require(access is "Allow" or "Deny", cap, p + ".accessType", "field.invalid-access-type");
                check.Require(flags is >= 0 and <= byte.MaxValue, cap, p + ".aceFlags", "field.invalid-ace-flags");
                if (!check.Known) { emitted = true; yield return check.Unknown() with { CheckKey = $"ace:{ace.AceIndex}" }; continue; }
                if (access == "Deny" || (flags & 8) != 0) continue;
                var trustee = check.Text(cap, p + ".trusteeSid", FactValueKind.Sid);
                var broad = BroadPrincipal.Matches(trustee, snapshot, check);
                if (!check.Known) { emitted = true; yield return check.Unknown() with { CheckKey = $"ace:{ace.AceIndex}" }; continue; }
                if (!broad) continue;
                var mask = check.Integer(cap, p + ".accessMask");
                check.Require(mask is >= 0 and <= uint.MaxValue, cap, p + ".accessMask", "field.invalid-access-mask");
                var objectTypePresent = check.Boolean(cap, p + ".objectTypePresent");
                string? objectType = null;
                if (check.Known && objectTypePresent)
                {
                    objectType = check.Text(cap, p + ".objectType", FactValueKind.Guid);
                    check.Require(Guid.TryParse(objectType, out _), cap, p + ".objectType", "field.invalid-guid");
                }
                // Verify the evidence and the typed inventory refer to the same ACE, rather than
                // silently choosing one if their fields disagree.
                check.Require(ace.AccessType.ToString() == access && ace.AceFlags == flags && ace.AccessMask == mask &&
                    StringComparer.OrdinalIgnoreCase.Equals(ace.TrusteeSid, trustee) && ace.ObjectType.HasValue == objectTypePresent &&
                    (!objectTypePresent || StringComparer.OrdinalIgnoreCase.Equals(ace.ObjectType?.ToString("D"), objectType)),
                    cap, p, "evidence.typed-content-conflict");
                if (!check.Known) { emitted = true; yield return check.Unknown() with { CheckKey = $"ace:{ace.AceIndex}" }; continue; }
                var full = (mask & 0x10000000) != 0 || (mask & 0x000F01FF) == 0x000F01FF;
                var match = _test switch
                {
                    AclTest.GenericAll => full,
                    AclTest.GenericWrite => (mask & (0x40000000 | 0x20)) != 0,
                    AclTest.WriteDacl => (mask & 0x40000) != 0,
                    AclTest.WriteOwner => (mask & 0x80000) != 0,
                    AclTest.ResetPassword => (subject is AdUser or AdComputer) && (mask & 0x100) != 0 &&
                        (!objectTypePresent || StringComparer.OrdinalIgnoreCase.Equals(objectType, "00299570-246d-11d0-a768-00aa006e0529")),
                    AclTest.ReplicationRight => (mask & 0x100) != 0 && (!objectTypePresent ||
                        StringComparer.OrdinalIgnoreCase.Equals(objectType, "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2") ||
                        StringComparer.OrdinalIgnoreCase.Equals(objectType, "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2") ||
                        StringComparer.OrdinalIgnoreCase.Equals(objectType, "89e95b76-444d-4c62-991a-0facbeda640c")),
                    _ => false
                };
                if (!match) continue;
                emitted = true;
                check.AddEvidence(descriptor.Result(RuleOutcome.NotDetected, "descriptor", "Descriptor context.").Evidence);
                yield return check.Verdict(true,
                    $"A non-inherit-only Allow ACE at source index {ace.AceIndex} names a broad principal ({trustee}) and carries the tested rights. " +
                    "Deny precedence, object-specific scope, token groups and effective access are not calculated. This is a potentially dangerous ACE, not proof of effective control or DCSync.",
                    potential: true, checkKey: $"ace:{ace.AceIndex}:{trustee}");
            }
            if (!emitted)
                yield return descriptor.Verdict(false, "No matching broad-principal Allow ACE was found in the fully parsed, explicitly counted DACL. This is not an effective-access audit.");
        }
    }
}
