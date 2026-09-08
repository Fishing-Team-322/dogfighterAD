using System.Globalization;
using DogfighterAD.Application.Contracts;
using DogfighterAD.Domain.Analysis;
using DogfighterAD.Domain.Findings;
using DogfighterAD.Domain.Snapshots;

namespace DogfighterAD.Application.Analysis.Rules;

public enum NumericComparison { Equals, LessThan }
public sealed record RegistryRuleDefinition(string Id, string KeyPath, string ValueName, NumericComparison Comparison,
    uint Threshold, FindingSeverity Severity, string Title, bool BothScopes = false, uint MaximumSupportedValue = 1);

public sealed class GpoRegistryRule : RuleBase
{
    private readonly RegistryRuleDefinition _definition;
    public GpoRegistryRule(RuleMetadata metadata, RegistryRuleDefinition definition) : base(metadata) => _definition = definition;
    public override IEnumerable<RuleEvaluation> Evaluate(AdSnapshot snapshot, RuleContext context)
    {
        const string cap = CollectionCapabilities.GroupPolicySysvol;
        var byGpo = snapshot.Content.GroupPolicySettings.GroupBy(s => s.GpoId).ToDictionary(g => g.Key, g => g.ToArray());
        foreach (var gpo in snapshot.Content.GroupPolicyObjects.OrderBy(g => g.Id.Value))
        {
            foreach (var scope in _definition.BothScopes ? new[] { GpoPolicyScope.Machine, GpoPolicyScope.User } : new[] { GpoPolicyScope.Machine })
            {
                var check = Check(context, gpo);
                var all = byGpo.TryGetValue(gpo.Id, out var settings) ? settings : [];
                var candidates = all.Where(s => s.Scope == scope && s.Kind == GpoSettingKind.RegistryPolicy &&
                    StringComparer.OrdinalIgnoreCase.Equals(s.Section, _definition.KeyPath) &&
                    StringComparer.OrdinalIgnoreCase.Equals(s.Key, _definition.ValueName)).ToArray();
                var path = $"{scope}:{_definition.KeyPath}\\{_definition.ValueName}";
                check.Require(candidates.Length > 0, cap, path, "policy.value-not-observed");
                // Without stored directive payloads an operation such as **DeleteValues cannot be
                // resolved safely. Do not invent the final state or pick an arbitrary duplicate.
                check.Require(!all.Any(s => s.Scope == scope && s.Kind == GpoSettingKind.RegistryPolicy &&
                    StringComparer.OrdinalIgnoreCase.Equals(s.Section, _definition.KeyPath) && s.Key.StartsWith("**", StringComparison.Ordinal)),
                    cap, path, "policy.unresolved-registry-operation");
                var values = new List<long>();
                foreach (var candidate in candidates)
                {
                    check.Require(candidate.Disposition == FactDisposition.Stored && candidate.ValueKind == FactValueKind.Integer &&
                        IsScopePath(scope, candidate.SourceRelativePath), cap, path, "policy.value-not-stored-or-invalid-scope");
                    var type = check.Integer(cap, SettingFactPath(candidate) + ".registryValueType");
                    check.Require(type == 4 && candidate.RegistryValueType == 4, cap, path + ".registryValueType", "policy.required-reg-dword-type-unavailable");
                    var value = check.Integer(cap, SettingFactPath(candidate));
                    check.Require(value is >= 0 and <= uint.MaxValue &&
                        long.TryParse(candidate.Value, NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture, out var typed) && typed == value,
                        cap, path, "evidence.typed-content-conflict");
                    values.Add(value);
                }
                check.Require(values.Distinct().Count() <= 1, cap, path, "policy.conflicting-assignments");
                if (!check.Known) { yield return check.Unknown() with { CheckKey = scope.ToString() }; continue; }
                var observed = values[0];
                check.Require(observed <= _definition.MaximumSupportedValue, cap, path, "policy.unsupported-enumerated-value");
                if (!check.Known) { yield return check.Unknown() with { CheckKey = scope.ToString() }; continue; }
                var match = _definition.Comparison == NumericComparison.Equals ? observed == _definition.Threshold : observed < _definition.Threshold;
                yield return check.Verdict(match,
                    $"Stored GPO assignment {path}={observed.ToString(CultureInfo.InvariantCulture)}. " +
                    "This is configuration evidence, not resultant policy: link/enforcement order, security/WMI filtering, loopback, disabled GPO sections, OS defaults, newer policy overrides and runtime/tamper protections are not resolved. " +
                    (_definition.ValueName == "AlwaysInstallElevated" ? "Both machine and user policy must be enabled for the well-known elevation condition; this check establishes only the stated side." : string.Empty),
                    potential: true, checkKey: scope.ToString());
            }
        }
    }
    internal static bool IsScopePath(GpoPolicyScope scope, string path) => path.StartsWith(scope + "\\", StringComparison.OrdinalIgnoreCase);
    internal static string SettingFactPath(AdGpoSetting setting)
    {
        var key = setting.Key.Replace("\\", "/", StringComparison.Ordinal);
        return $"gpo.sysvol.setting.{setting.SourceRelativePath}.{setting.Sequence}.{key}";
    }
}

public sealed class GppSecretRule : RuleBase
{
    public GppSecretRule(RuleMetadata metadata) : base(metadata) { }
    public override IEnumerable<RuleEvaluation> Evaluate(AdSnapshot snapshot, RuleContext context)
    {
        const string cap = CollectionCapabilities.GroupPolicySysvol;
        var gpos = snapshot.Content.GroupPolicyObjects.ToDictionary(g => g.Id);
        var byFile = snapshot.Content.GroupPolicySettings.GroupBy(s => (s.GpoId, s.SourceRelativePath.ToUpperInvariant()))
            .ToDictionary(g => g.Key, g => g.ToArray());
        foreach (var file in snapshot.Content.GroupPolicyFiles.Where(f => f.Kind == GpoSysvolFileKind.PreferencesXml)
                     .OrderBy(f => f.GpoId.Value).ThenBy(f => f.RelativePath, StringComparer.Ordinal))
        {
            var gpo = gpos[file.GpoId];
            var check = Check(context, gpo);
            var settings = (byFile.TryGetValue((file.GpoId, file.RelativePath.ToUpperInvariant()), out var entries) ? entries : [])
                .Where(s => s.Kind == GpoSettingKind.PreferenceSignal && s.Key == "cpassword-present").ToArray();
            check.Require(settings.Length == 1, cap, file.RelativePath + ":cpassword-present", "policy.signal-missing-or-ambiguous");
            if (!check.Known) { yield return check.Unknown() with { CheckKey = file.RelativePath.ToUpperInvariant() }; continue; }
            var value = check.Boolean(cap, GpoRegistryRule.SettingFactPath(settings[0]));
            check.Require(settings[0].Disposition == FactDisposition.Stored &&
                bool.TryParse(settings[0].Value, out var typed) && typed == value, cap, file.RelativePath, "evidence.typed-content-conflict");
            yield return check.Verdict(value,
                "A fully parsed Group Policy Preferences XML file was checked for a nonempty cpassword attribute. " +
                "Only its presence signal is stored. Ciphertext validity and a usable password are not established; remove legacy secrets and rotate affected credentials.",
                checkKey: file.RelativePath.ToUpperInvariant());
        }
        if (snapshot.Content.GroupPolicyObjects.Count > 0 && snapshot.Content.GroupPolicyFiles.Count == 0)
        {
            var check = Check(context, AnalysisSubjects.Snapshot(snapshot));
            check.Require(false, cap, "gpo.sysvol.file", "policy.file-inventory-unavailable"); yield return check.Unknown();
        }
    }
}

public sealed class GpoPrivilegeRule : RuleBase
{
    private readonly string _privilege;
    public GpoPrivilegeRule(RuleMetadata metadata, string privilege) : base(metadata) => _privilege = privilege;
    public override IEnumerable<RuleEvaluation> Evaluate(AdSnapshot snapshot, RuleContext context)
    {
        const string cap = CollectionCapabilities.GroupPolicySysvol;
        var byGpo = snapshot.Content.GroupPolicySettings.GroupBy(x => x.GpoId).ToDictionary(g => g.Key, g => g.ToArray());
        foreach (var gpo in snapshot.Content.GroupPolicyObjects.OrderBy(g => g.Id.Value))
        {
            var check = Check(context, gpo);
            var candidates = (byGpo.TryGetValue(gpo.Id, out var settings) ? settings : [])
                .Where(s => s.Kind == GpoSettingKind.SecurityTemplate && s.Scope == GpoPolicyScope.Machine &&
                    StringComparer.OrdinalIgnoreCase.Equals(s.Section, "Privilege Rights") && s.Key == _privilege).ToArray();
            check.Require(candidates.Length == 1, cap, "Privilege Rights/" + _privilege, "policy.value-missing-or-ambiguous");
            if (!check.Known) { yield return check.Unknown(); continue; }
            var value = check.Text(cap, GpoRegistryRule.SettingFactPath(candidates[0]));
            check.Require(candidates[0].Disposition == FactDisposition.Stored && candidates[0].Value == value,
                cap, _privilege, "evidence.typed-content-conflict");
            if (!check.Known) { yield return check.Unknown(); continue; }
            string[] sids = value.Length == 0 ? [] : value.Split(',').Select(x => x.Trim().TrimStart('*')).ToArray();
            check.Require(sids.All(IsSid), cap, _privilege, "policy.sid-list-invalid");
            var broad = false;
            foreach (var sid in sids) broad |= BroadPrincipal.Matches(sid, snapshot, check);
            yield return check.Verdict(broad, $"Stored GPO privilege assignment {_privilege} was evaluated against the documented broad-principal set. " +
                "Empty assignments are evaluated only when explicitly stored. Actual computer policy application and effective token privileges are not established.", potential: true);
        }
    }
    private static bool IsSid(string value)
    {
        var p = value.Split('-');
        return p.Length is >= 4 and <= 18 && p[0] == "S" && p[1] == "1" &&
            ulong.TryParse(p[2], NumberStyles.None, CultureInfo.InvariantCulture, out var authority) && authority <= 0xffffffffffffUL &&
            p.Skip(3).All(x => uint.TryParse(x, NumberStyles.None, CultureInfo.InvariantCulture, out _));
    }
}

public sealed class GpoVersionRule : RuleBase
{
    public GpoVersionRule(RuleMetadata metadata) : base(metadata) { }
    public override IEnumerable<RuleEvaluation> Evaluate(AdSnapshot snapshot, RuleContext context)
    {
        var byGpo = snapshot.Content.GroupPolicySettings.GroupBy(s => s.GpoId).ToDictionary(g => g.Key, g => g.ToArray());
        foreach (var gpo in snapshot.Content.GroupPolicyObjects.OrderBy(g => g.Id.Value))
        {
            var check = Check(context, gpo);
            var ldap = check.Integer(CollectionCapabilities.GroupPolicyMetadata, "gpo.versionNumber");
            var settings = (byGpo.TryGetValue(gpo.Id, out var entries) ? entries : []).Where(s => s.Kind == GpoSettingKind.Ini &&
                StringComparer.OrdinalIgnoreCase.Equals(s.SourceRelativePath, "GPT.INI") && StringComparer.OrdinalIgnoreCase.Equals(s.Section, "General") && StringComparer.OrdinalIgnoreCase.Equals(s.Key, "Version")).ToArray();
            check.Require(settings.Length == 1, CollectionCapabilities.GroupPolicySysvol, "GPT.INI/General/Version", "policy.version-missing-or-ambiguous");
            if (!check.Known) { yield return check.Unknown(); continue; }
            var text = check.Text(CollectionCapabilities.GroupPolicySysvol, GpoRegistryRule.SettingFactPath(settings[0]));
            check.Require(ldap is >= int.MinValue and <= uint.MaxValue &&
                uint.TryParse(text, NumberStyles.None, CultureInfo.InvariantCulture, out _), CollectionCapabilities.GroupPolicySysvol,
                "GPT.INI/General/Version", "field.invalid-version");
            check.Require(settings[0].Disposition == FactDisposition.Stored && settings[0].Value == text,
                CollectionCapabilities.GroupPolicySysvol, "GPT.INI/General/Version", "evidence.typed-content-conflict");
            if (!check.Known) { yield return check.Unknown(); continue; }
            var sysvol = uint.Parse(text, CultureInfo.InvariantCulture);
            var mismatch = unchecked((uint)ldap) != sysvol;
            yield return check.Verdict(mismatch,
                mismatch ? "The explicitly observed LDAP and GPT.INI GPO version values differ. This can result from replication delay or concurrent edits; it is not proof of tampering."
                    : "The explicitly observed LDAP and GPT.INI version values agree. This does not prove the content is authentic or current on every DC.", potential: true);
        }
    }
}
