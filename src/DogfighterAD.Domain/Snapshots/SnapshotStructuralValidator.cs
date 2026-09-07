namespace DogfighterAD.Domain.Snapshots;

public static class SnapshotStructuralValidator
{
    public static IReadOnlyList<SnapshotInvariantViolation> Validate(AdSnapshot snapshot)
    {
        ArgumentNullException.ThrowIfNull(snapshot);

        var violations = new List<SnapshotInvariantViolation>();
        var metadata = snapshot.Metadata;
        var content = snapshot.Content;
        var coverage = snapshot.Coverage;
        var observations = snapshot.Observations;

        if (metadata is null)
        {
            violations.Add(Missing("metadata"));
        }
        else
        {
            if (metadata.Target is null)
            {
                violations.Add(Missing("metadata.target"));
            }

            RequireList(metadata.RequestedCapabilities, "metadata.requestedCapabilities", violations);
            RequireList(metadata.Collectors, "metadata.collectors", violations);
        }

        if (content is null)
        {
            violations.Add(Missing("content"));
        }
        else
        {
            ValidateContent(content, violations);
        }

        if (RequireList(coverage, "coverage", violations))
        {
            for (var index = 0; index < coverage.Count; index++)
            {
                var item = coverage[index];
                if (item is null)
                {
                    continue;
                }

                RequireList(item.Collectors, $"coverage[{index}].collectors", violations);
                RequireList(item.Issues, $"coverage[{index}].issues", violations);
            }
        }

        if (RequireList(observations, "observations", violations))
        {
            for (var index = 0; index < observations.Count; index++)
            {
                var fact = observations[index];
                if (fact is not null && fact.Source is null)
                {
                    violations.Add(Missing($"observations[{index}].source"));
                }
            }
        }

        return violations;
    }

    private static void ValidateContent(
        SnapshotContent content,
        ICollection<SnapshotInvariantViolation> violations)
    {
        RequireList(content.Domains, "content.domains", violations);
        var usersValid = RequireList(content.Users, "content.users", violations);
        RequireList(content.Groups, "content.groups", violations);
        var computersValid = RequireList(content.Computers, "content.computers", violations);
        RequireList(content.OrganizationalUnits, "content.organizationalUnits", violations);
        RequireList(content.GroupPolicyObjects, "content.groupPolicyObjects", violations);
        RequireList(content.ForeignSecurityPrincipals, "content.foreignSecurityPrincipals", violations);
        RequireList(content.OtherDirectoryObjects, "content.otherDirectoryObjects", violations);
        RequireList(content.GroupMemberships, "content.groupMemberships", violations);
        RequireList(content.GroupPolicyLinks, "content.groupPolicyLinks", violations);
        RequireList(content.GroupPolicyContainerPolicies, "content.groupPolicyContainerPolicies", violations);
        RequireList(content.GroupPolicyFiles, "content.groupPolicyFiles", violations);
        RequireList(content.GroupPolicySettings, "content.groupPolicySettings", violations);
        RequireList(content.Trusts, "content.trusts", violations);
        RequireList(content.SecurityDescriptors, "content.securityDescriptors", violations);
        RequireList(content.Aces, "content.aces", violations);

        if (content.DirectoryEnvironment is { } environment)
        {
            RequireList(environment.NamingContexts, "content.directoryEnvironment.namingContexts", violations);
            RequireList(environment.SupportedCapabilities, "content.directoryEnvironment.supportedCapabilities", violations);
            RequireList(environment.SupportedControls, "content.directoryEnvironment.supportedControls", violations);
            RequireList(environment.SupportedLdapVersions, "content.directoryEnvironment.supportedLdapVersions", violations);
        }

        if (usersValid)
        {
            for (var index = 0; index < content.Users.Count; index++)
            {
                var user = content.Users[index];
                if (user is null)
                {
                    continue;
                }

                RequireList(user.ServicePrincipalNames, $"content.users[{index}].servicePrincipalNames", violations);
                RequireList(user.SidHistory, $"content.users[{index}].sidHistory", violations);
                RequireList(user.AllowedToDelegateTo, $"content.users[{index}].allowedToDelegateTo", violations);
            }
        }

        if (computersValid)
        {
            for (var index = 0; index < content.Computers.Count; index++)
            {
                var computer = content.Computers[index];
                if (computer is null)
                {
                    continue;
                }

                RequireList(computer.ServicePrincipalNames, $"content.computers[{index}].servicePrincipalNames", violations);
                RequireList(computer.AllowedToDelegateTo, $"content.computers[{index}].allowedToDelegateTo", violations);
            }
        }
    }

    private static bool RequireList<T>(
        IReadOnlyList<T>? values,
        string path,
        ICollection<SnapshotInvariantViolation> violations)
        where T : class
    {
        if (values is null)
        {
            violations.Add(Missing(path));
            return false;
        }

        for (var index = 0; index < values.Count; index++)
        {
            if (values[index] is null)
            {
                violations.Add(new SnapshotInvariantViolation(
                    "snapshot.structure.null-element",
                    $"Snapshot array '{path}' contains null element at index {index}."));
            }
        }

        return true;
    }

    private static SnapshotInvariantViolation Missing(string path) =>
        new(
            "snapshot.structure.required-missing",
            $"Snapshot required object or array '{path}' is missing.");
}
