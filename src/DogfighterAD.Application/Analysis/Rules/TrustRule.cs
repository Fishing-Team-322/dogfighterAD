using DogfighterAD.Application.Contracts;
using DogfighterAD.Domain.Analysis;
using DogfighterAD.Domain.Findings;
using DogfighterAD.Domain.Snapshots;

namespace DogfighterAD.Application.Analysis.Rules;

public enum TrustTest { ExternalWithoutSelectiveAuthentication, TreatAsExternal, TgtDelegationEnabled, LegacyTrustType }
public sealed class TrustRule : RuleBase
{
    private readonly TrustTest _test;
    public TrustRule(RuleMetadata metadata, TrustTest test) : base(metadata) => _test = test;
    public override IEnumerable<RuleEvaluation> Evaluate(AdSnapshot snapshot, RuleContext context)
    {
        const string cap = CollectionCapabilities.DirectoryTrusts;
        var subjects = context.Facts.Subjects(cap, "trust.partner");
        if (snapshot.Content.Trusts.Count != subjects.Count)
        {
            var missing = Check(context, AnalysisSubjects.Snapshot(snapshot));
            missing.Require(false, cap, "trust.partner", "field.not-observed"); yield return missing.Unknown() with { CheckKey = "inventory" };
        }
        foreach (var subject in subjects)
        {
            var check = Check(context, new ObjectReference("trust", subject));
            var partner = check.Text(cap, "trust.partner");
            var direction = check.Integer(cap, "trust.direction");
            var attributes = check.Integer(cap, "trust.attributes");
            var type = check.Integer(cap, "trust.type");
            check.Require(direction is >= 0 and <= 3 && attributes is >= 0 and <= uint.MaxValue && type is >= 1 and <= 4,
                cap, "trust.attributes/type/direction", "field.invalid-trust-data");
            if (!check.Known) { yield return check.Unknown(); continue; }
            // OUTBOUND means this domain trusts the partner. INBOUND alone does not grant the
            // partner access here and must not be described as such.
            if (_test == TrustTest.ExternalWithoutSelectiveAuthentication && ((direction & 2) == 0 || (attributes & 0x20) != 0))
            { yield return check.NotApplicable("Not an outbound trust to a domain outside the current forest."); continue; }
            var match = _test switch
            {
                TrustTest.ExternalWithoutSelectiveAuthentication => (attributes & 0x10) == 0,
                TrustTest.TreatAsExternal => (attributes & (0x8 | 0x40)) == (0x8 | 0x40),
                TrustTest.TgtDelegationEnabled => (attributes & 0x800) != 0,
                TrustTest.LegacyTrustType => type == 1,
                _ => false
            };
            yield return check.Verdict(match, $"Trust partner={partner}, direction={direction}, type={type}, attributes=0x{attributes:X}. " +
                "This evaluates the local TDO configuration. It does not establish the remote domain's settings, effective SID filtering, network reachability or exploitable delegation.", potential: true);
        }
    }
}
