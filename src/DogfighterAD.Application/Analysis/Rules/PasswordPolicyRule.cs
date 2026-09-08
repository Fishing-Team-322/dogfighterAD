using System.Globalization;
using DogfighterAD.Application.Contracts;
using DogfighterAD.Domain.Analysis;
using DogfighterAD.Domain.Findings;
using DogfighterAD.Domain.Snapshots;

namespace DogfighterAD.Application.Analysis.Rules;

public enum PasswordPolicyTest { Length, History, Complexity, Reversible, LockoutDisabled, LockoutHigh, LockoutDuration, MachineQuota }

public sealed class PasswordPolicyRule : RuleBase
{
    private readonly PasswordPolicyTest _test;
    public PasswordPolicyRule(RuleMetadata metadata, PasswordPolicyTest test) : base(metadata) => _test = test;
    public override IEnumerable<RuleEvaluation> Evaluate(AdSnapshot snapshot, RuleContext context)
    {
        const string cap = CollectionCapabilities.DirectorySecurityPolicy;
        var subjects = snapshot.Content.Domains.Select(d => AnalysisSubjects.For(d))
            .Concat(context.Facts.Subjects(cap, "policy.kind").Where(s => s.StartsWith("password-policy:", StringComparison.Ordinal))
                .Select(s => new ObjectReference("fine-grained-password-policy", s)))
            .DistinctBy(x => x.StableId, StringComparer.Ordinal).OrderBy(x => x.StableId, StringComparer.Ordinal);
        foreach (var subject in subjects)
        {
            var check = Check(context, subject);
            var kind = check.Text(cap, "policy.kind");
            check.Text(cap, "policy.distinguishedName", FactValueKind.DistinguishedName);
            check.Require(kind is "DefaultDomain" or "FineGrained", cap, "policy.kind", "field.invalid-policy-kind");
            if (!check.Known) { yield return check.Unknown(); continue; }
            if (_test == PasswordPolicyTest.MachineQuota && kind != "DefaultDomain")
            { yield return check.NotApplicable("Machine-account quota is a domain property, not a PSO property."); continue; }
            var field = _test switch
            {
                PasswordPolicyTest.Length => "minimumPasswordLength", PasswordPolicyTest.History => "passwordHistoryLength",
                PasswordPolicyTest.Complexity => "complexityEnabled", PasswordPolicyTest.Reversible => "reversibleEncryptionEnabled",
                PasswordPolicyTest.MachineQuota => "machineAccountQuota", PasswordPolicyTest.LockoutDuration => "lockoutDurationTicks",
                _ => "lockoutThreshold"
            };
            bool match;
            string condition;
            if (_test is PasswordPolicyTest.Complexity or PasswordPolicyTest.Reversible)
            {
                var value = check.Boolean(cap, "policy." + field);
                match = _test == PasswordPolicyTest.Complexity ? !value : value;
                condition = $"{field}={value.ToString().ToLowerInvariant()}";
            }
            else
            {
                var value = check.Integer(cap, "policy." + field);
                check.Require(_test == PasswordPolicyTest.LockoutDuration ? value <= 0 : value is >= 0 and <= int.MaxValue,
                    cap, "policy." + field, "field.invalid-policy-range");
                if (_test == PasswordPolicyTest.LockoutDuration)
                {
                    var threshold = check.Integer(cap, "policy.lockoutThreshold");
                    check.Require(threshold is >= 0 and <= int.MaxValue, cap, "policy.lockoutThreshold", "field.invalid-policy-range");
                    if (check.Known && threshold == 0)
                    { yield return check.NotApplicable("Lockout is explicitly disabled; handled by the lockout-disabled rule."); continue; }
                }
                match = _test switch
                {
                    PasswordPolicyTest.Length => value < context.Policy.MinimumPasswordLength,
                    PasswordPolicyTest.History => value < context.Policy.MinimumPasswordHistory,
                    PasswordPolicyTest.LockoutDisabled => value == 0,
                    PasswordPolicyTest.LockoutHigh => value > context.Policy.MaximumLockoutThreshold,
                    PasswordPolicyTest.LockoutDuration => value != 0 && value > -TimeSpan.FromMinutes(context.Policy.MinimumLockoutMinutes).Ticks,
                    PasswordPolicyTest.MachineQuota => value > 0,
                    _ => false
                };
                condition = $"{field}={value.ToString(CultureInfo.InvariantCulture)} (compared with the explicit analysis policy)";
            }
            yield return check.Verdict(match, $"{kind} policy: {condition}. " +
                "This evaluates a stored policy configuration, not the resultant policy of every user. PSO assignment/precedence and local policy are not inferred.",
                potential: _test != PasswordPolicyTest.Reversible);
        }
    }
}
