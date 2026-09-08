using System.Globalization;
using DogfighterAD.Application.Contracts;
using DogfighterAD.Domain.Analysis;
using DogfighterAD.Domain.Findings;
using DogfighterAD.Domain.Snapshots;

namespace DogfighterAD.Application.Analysis.Rules;

public enum AccountTest { Flag, ValuesPresent, EncryptionBit, PasswordAge, LogonAge, Expired, GuestEnabled, KrbtgtPasswordAge }

public sealed class AccountRule : RuleBase
{
    private readonly bool _computer;
    private readonly AccountTest _test;
    private readonly string _path;
    private readonly long _mask;
    private readonly bool _excludeDc;
    private readonly FactValueKind _kind;
    private string Capability => _computer ? CollectionCapabilities.DirectoryComputers : CollectionCapabilities.DirectoryUsers;
    private string Prefix => _computer ? "computer" : "user";

    public AccountRule(RuleMetadata metadata, bool computer, AccountTest test, string path = "",
        long mask = 0, bool excludeDc = false, FactValueKind kind = FactValueKind.Text) : base(metadata with { Version = "1.0.1" })
    { _computer = computer; _test = test; _path = path; _mask = mask; _excludeDc = excludeDc; _kind = kind; }

    public override IEnumerable<RuleEvaluation> Evaluate(AdSnapshot snapshot, RuleContext context)
    {
        IEnumerable<AdDirectoryObject> subjects = _computer ? snapshot.Content.Computers : snapshot.Content.Users;
        foreach (var subject in subjects.OrderBy(x => x.Id.Value))
        {
            context.CancellationToken.ThrowIfCancellationRequested();
            var check = Check(context, subject);
            var uac = check.Integer(Capability, Prefix + ".userAccountControl");
            check.Require(uac is >= 0 and <= uint.MaxValue, Capability, Prefix + ".userAccountControl", "field.invalid-uac");
            if (!check.Known) { yield return check.Unknown(); continue; }
            if ((uac & 2) != 0 && _test != AccountTest.KrbtgtPasswordAge) { yield return check.NotApplicable("The account is explicitly disabled in the observed UAC."); continue; }
            if (_excludeDc && (uac & (0x2000 | 0x04000000)) != 0)
            { yield return check.NotApplicable("Domain controller/RODC account excluded from the non-DC delegation rule."); continue; }

            if (_test is AccountTest.GuestEnabled or AccountTest.KrbtgtPasswordAge)
            {
                var sid = check.Text(Capability, "object.objectSid", FactValueKind.Sid);
                var domainSids = snapshot.Content.Domains.Select(domain => check.Text(CollectionCapabilities.DirectoryDomains,
                    "domain.objectSid", FactValueKind.Sid, $"ad-object:{domain.Id}")).ToArray();
                check.Require(domainSids.Length > 0, CollectionCapabilities.DirectoryDomains, "domain.objectSid", "field.not-observed");
                if (!check.Known) { yield return check.Unknown(); continue; }
                var rid = _test == AccountTest.GuestEnabled ? "501" : "502";
                if (!domainSids.Any(d => StringComparer.OrdinalIgnoreCase.Equals(sid, d + "-" + rid)))
                { yield return check.NotApplicable("Account SID is not the domain's well-known account targeted by this rule."); continue; }
                if (_test == AccountTest.GuestEnabled)
                { yield return check.Verdict(true, "The domain Guest account is explicitly enabled. This does not prove that any particular resource permits guest access."); continue; }
            }

            if (_test == AccountTest.Flag)
            {
                yield return check.Verdict((uac & _mask) != 0,
                    $"Observed UAC={uac.ToString(CultureInfo.InvariantCulture)}; tested mask=0x{_mask:X}. The finding concerns a configured account flag, not successful exploitation.");
            }
            else if (_test == AccountTest.ValuesPresent)
            {
                var values = check.Values(Capability, Prefix + "." + _path, _kind);
                check.Require(values.All(v => !string.IsNullOrWhiteSpace(v)), Capability, Prefix + "." + _path, "field.empty-value");
                yield return check.Verdict(values.Count > 0,
                    "An enabled account has explicitly observed values for " + Prefix + "." + _path +
                    ". This is an exposure/review signal; secret strength, target reachability and exploitability are not established.", potential: true);
            }
            else if (_test == AccountTest.EncryptionBit)
            {
                var value = check.Integer(Capability, Prefix + ".supportedEncryptionTypes");
                if (!check.Known) { yield return check.Unknown(); continue; }
                // Explicit zero uses environment-dependent defaults; missing/zero is never converted to RC4 or AES.
                check.Require(value is > 0 and <= uint.MaxValue, Capability, Prefix + ".supportedEncryptionTypes", "field.zero-or-invalid-encryption-mask");
                yield return check.Verdict((value & _mask) != 0,
                    $"Explicit encryption capability mask={value.ToString(CultureInfo.InvariantCulture)}; tested mask=0x{_mask:X}. This does not identify negotiated encryption or installed key material.");
            }
            else
            {
                var field = _test == AccountTest.LogonAge ? "lastLogonTimestamp" : _test == AccountTest.Expired ? "accountExpires" : "pwdLastSet";
                var raw = check.Integer(Capability, Prefix + "." + field);
                if (!check.Known) { yield return check.Unknown(); continue; }
                if (_test == AccountTest.Expired && raw is 0 or long.MaxValue)
                { yield return check.Verdict(false, "The explicitly observed accountExpires sentinel means no account expiration."); continue; }
                DateTimeOffset stamp = default;
                var valid = raw > 0;
                if (valid)
                {
                    try { stamp = DateTimeOffset.FromFileTime(raw); }
                    catch (ArgumentOutOfRangeException) { valid = false; }
                }
                if (_test != AccountTest.Expired) valid &= stamp <= snapshot.Metadata.CompletedAt;
                check.Require(valid, Capability, Prefix + "." + field, "field.no-valid-event-timestamp");
                if (!check.Known) { yield return check.Unknown(); continue; }
                if (_test == AccountTest.Expired)
                { yield return check.Verdict(stamp <= context.AnalysisTime, "The explicitly observed account-expiration timestamp was compared with the analysis reference time; the configured UAC is enabled.", potential: true); continue; }
                var threshold = _test switch
                {
                    AccountTest.LogonAge => context.Policy.ReplicatedLogonAgeDays,
                    AccountTest.KrbtgtPasswordAge => context.Policy.KrbtgtPasswordAgeDays,
                    _ => _computer ? context.Policy.ComputerPasswordAgeDays : context.Policy.UserPasswordAgeDays
                };
                yield return check.Verdict(context.AnalysisTime - stamp > TimeSpan.FromDays(threshold),
                    $"Observed {field}={stamp:O}; organizational review threshold={threshold} days; reference={context.AnalysisTime:O}. " +
                    (_test == AccountTest.LogonAge ? "Replicated lastLogonTimestamp is approximate and does not prove inactivity or absence of recent authentication." :
                    _test == AccountTest.KrbtgtPasswordAge ? "Plan a controlled krbtgt rotation procedure; do not reset it twice immediately." :
                    "Age alone does not prove compromise and is not a recommendation for indiscriminate periodic password expiry."), potential: true);
            }
        }
    }
}
