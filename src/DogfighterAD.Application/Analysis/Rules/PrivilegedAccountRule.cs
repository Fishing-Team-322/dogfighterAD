using DogfighterAD.Application.Contracts;
using DogfighterAD.Domain.Analysis;
using DogfighterAD.Domain.Snapshots;

namespace DogfighterAD.Application.Analysis.Rules;

public enum PrivilegedAccountTest { DelegationNotBlocked, ServicePrincipalName, PasswordNeverExpires }
public sealed class PrivilegedAccountRule : RuleBase
{
    private readonly PrivilegedAccountTest _test;
    public PrivilegedAccountRule(RuleMetadata metadata, PrivilegedAccountTest test) : base(metadata) => _test = test;
    public override IEnumerable<RuleEvaluation> Evaluate(AdSnapshot snapshot, RuleContext context)
    {
        context.MembershipIndex ??= new PrivilegedMembershipIndex(snapshot, context.Facts, context.CancellationToken);
        foreach (var user in snapshot.Content.Users.OrderBy(x => x.Id.Value))
        {
            var check = Check(context, user);
            var uac = check.Integer(CollectionCapabilities.DirectoryUsers, "user.userAccountControl");
            check.Require(uac is >= 0 and <= uint.MaxValue, CollectionCapabilities.DirectoryUsers, "user.userAccountControl", "field.invalid-uac");
            if (!check.Known) { yield return check.Unknown(); continue; }
            if ((uac & 2) != 0) { yield return check.NotApplicable("The user is explicitly disabled."); continue; }
            if (!context.MembershipIndex.TryProve(user.Id, out var membershipEvidence))
            {
                if (context.MembershipIndex.ScopeComplete)
                    yield return check.NotApplicable("No path to the documented privileged-group roots exists in the complete, evidence-backed in-scope membership graph. This is not a forest-wide non-privilege assertion.");
                else
                {
                    check.Require(false, CollectionCapabilities.DirectoryMemberships, "membership.path", "membership.proof-incomplete");
                    yield return check.Unknown();
                }
                continue;
            }
            check.AddEvidence(membershipEvidence);
            var match = _test switch
            {
                PrivilegedAccountTest.DelegationNotBlocked => (uac & 0x100000) == 0,
                PrivilegedAccountTest.PasswordNeverExpires => (uac & 0x10000) != 0,
                _ => check.Values(CollectionCapabilities.DirectoryUsers, "user.servicePrincipalName").Count > 0
            };
            yield return check.Verdict(match,
                "The account condition was evaluated for an enabled user with a proved membership path to an in-scope privileged group. " +
                "adminCount is not used as proof of privilege. Protected Users, authentication policies and effective runtime protections are not inferred.", potential: true);
        }
    }
}
