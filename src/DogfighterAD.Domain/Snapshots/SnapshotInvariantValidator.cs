namespace DogfighterAD.Domain.Snapshots;

public static class SnapshotInvariantValidator
{
    public static IReadOnlyList<SnapshotInvariantViolation> Validate(AdSnapshot snapshot)
    {
        ArgumentNullException.ThrowIfNull(snapshot);

        var violations = new List<SnapshotInvariantViolation>();

        if (snapshot.Metadata.SchemaVersion != SnapshotSchema.CurrentVersion)
        {
            violations.Add(new(
                "snapshot.schema.unsupported",
                $"Snapshot schema {snapshot.Metadata.SchemaVersion} does not match supported schema {SnapshotSchema.CurrentVersion}."));
        }

        if (snapshot.Metadata.CompletedAt < snapshot.Metadata.StartedAt)
        {
            violations.Add(new(
                "snapshot.time.invalid",
                "Snapshot completion time is earlier than start time."));
        }

        if (string.IsNullOrWhiteSpace(snapshot.Metadata.Target.InitialTarget))
        {
            violations.Add(new(
                "snapshot.target.missing",
                "Snapshot initial target must be present."));
        }

        ValidateDirectoryObjectIdentities(snapshot.Content, violations);
        ValidateRelationships(snapshot.Content, violations);
        ValidateObservations(snapshot.Observations, violations);
        ValidateCoverage(snapshot.Coverage, snapshot.Metadata.RequestedCapabilities, violations);

        return violations;
    }

    private static void ValidateDirectoryObjectIdentities(
        SnapshotContent content,
        ICollection<SnapshotInvariantViolation> violations)
    {
        var seen = new Dictionary<AdObjectId, string>();

        AddObjects(content.Domains, "domain", seen, violations);
        AddObjects(content.Users, "user", seen, violations);
        AddObjects(content.Groups, "group", seen, violations);
        AddObjects(content.Computers, "computer", seen, violations);
        AddObjects(content.OrganizationalUnits, "organizational-unit", seen, violations);
        AddObjects(content.GroupPolicyObjects, "group-policy-object", seen, violations);
        AddObjects(content.ForeignSecurityPrincipals, "foreign-security-principal", seen, violations);
        AddObjects(content.OtherDirectoryObjects, "generic-directory-object", seen, violations);
    }

    private static void AddObjects<T>(
        IEnumerable<T> objects,
        string kind,
        IDictionary<AdObjectId, string> seen,
        ICollection<SnapshotInvariantViolation> violations)
        where T : AdDirectoryObject
    {
        foreach (var item in objects)
        {
            if (!seen.TryAdd(item.Id, kind))
            {
                violations.Add(new(
                    "snapshot.object.duplicate-id",
                    $"AD object id {item.Id} appears more than once ({seen[item.Id]} and {kind})."));
            }

            if (string.IsNullOrWhiteSpace(item.DistinguishedName))
            {
                violations.Add(new(
                    "snapshot.object.missing-dn",
                    $"AD object {item.Id} ({kind}) has no distinguished name."));
            }
        }
    }

    private static void ValidateRelationships(
        SnapshotContent content,
        ICollection<SnapshotInvariantViolation> violations)
    {
        var knownObjectIds = EnumerateDirectoryObjects(content)
            .Select(x => x.Id)
            .ToHashSet();

        var knownGroupIds = content.Groups.Select(x => x.Id).ToHashSet();
        var knownGpoIds = content.GroupPolicyObjects.Select(x => x.Id).ToHashSet();

        foreach (var membership in content.GroupMemberships)
        {
            if (!knownGroupIds.Contains(membership.GroupId))
            {
                violations.Add(new(
                    "snapshot.membership.unknown-group",
                    $"Membership references unknown group {membership.GroupId}."));
            }

            if (!knownObjectIds.Contains(membership.MemberId))
            {
                violations.Add(new(
                    "snapshot.membership.unknown-member",
                    $"Membership references unknown member {membership.MemberId}."));
            }
        }

        foreach (var link in content.GroupPolicyLinks)
        {
            if (!knownObjectIds.Contains(link.ContainerId))
            {
                violations.Add(new(
                    "snapshot.gpo-link.unknown-container",
                    $"GPO link references unknown container {link.ContainerId}."));
            }

            if (!knownGpoIds.Contains(link.GpoId))
            {
                violations.Add(new(
                    "snapshot.gpo-link.unknown-gpo",
                    $"GPO link references unknown GPO {link.GpoId}."));
            }
        }

        foreach (var ace in content.Aces)
        {
            if (!knownObjectIds.Contains(ace.TargetObjectId))
            {
                violations.Add(new(
                    "snapshot.ace.unknown-target",
                    $"ACE references unknown target object {ace.TargetObjectId}."));
            }

            if (string.IsNullOrWhiteSpace(ace.TrusteeSid))
            {
                violations.Add(new(
                    "snapshot.ace.missing-trustee",
                    $"ACE for target {ace.TargetObjectId} has no trustee SID."));
            }
        }
    }

    private static IEnumerable<AdDirectoryObject> EnumerateDirectoryObjects(SnapshotContent content)
    {
        return content.Domains.Cast<AdDirectoryObject>()
            .Concat(content.Users)
            .Concat(content.Groups)
            .Concat(content.Computers)
            .Concat(content.OrganizationalUnits)
            .Concat(content.GroupPolicyObjects)
            .Concat(content.ForeignSecurityPrincipals)
            .Concat(content.OtherDirectoryObjects);
    }

    private static void ValidateObservations(
        IReadOnlyList<ObservedFact> observations,
        ICollection<SnapshotInvariantViolation> violations)
    {
        var factIds = new HashSet<string>(StringComparer.Ordinal);

        foreach (var fact in observations)
        {
            if (string.IsNullOrWhiteSpace(fact.FactId))
            {
                violations.Add(new(
                    "snapshot.fact.missing-id",
                    "Observed fact has no fact id."));
                continue;
            }

            if (!factIds.Add(fact.FactId))
            {
                violations.Add(new(
                    "snapshot.fact.duplicate-id",
                    $"Observed fact id '{fact.FactId}' is duplicated."));
            }

            if (string.IsNullOrWhiteSpace(fact.CapabilityId))
            {
                violations.Add(new(
                    "snapshot.fact.missing-capability",
                    $"Observed fact '{fact.FactId}' has no capability id."));
            }

            if (string.IsNullOrWhiteSpace(fact.Path))
            {
                violations.Add(new(
                    "snapshot.fact.missing-path",
                    $"Observed fact '{fact.FactId}' has no path."));
            }

            if ((fact.Disposition is FactDisposition.Redacted or FactDisposition.MetadataOnly) &&
                fact.Value is not null)
            {
                violations.Add(new(
                    "snapshot.fact.redaction-invalid",
                    $"Observed fact '{fact.FactId}' is {fact.Disposition} but still contains a value."));
            }
        }
    }

    private static void ValidateCoverage(
        IReadOnlyList<CapabilityCoverage> coverage,
        IReadOnlyList<string> requestedCapabilities,
        ICollection<SnapshotInvariantViolation> violations)
    {
        var capabilityIds = new HashSet<string>(StringComparer.Ordinal);

        foreach (var item in coverage)
        {
            if (string.IsNullOrWhiteSpace(item.CapabilityId))
            {
                violations.Add(new(
                    "snapshot.coverage.missing-capability-id",
                    "Coverage record has no capability id."));
                continue;
            }

            if (!capabilityIds.Add(item.CapabilityId))
            {
                violations.Add(new(
                    "snapshot.coverage.duplicate-capability",
                    $"Capability coverage '{item.CapabilityId}' appears more than once."));
            }

            if (item.CompletedAt < item.StartedAt)
            {
                violations.Add(new(
                    "snapshot.coverage.time-invalid",
                    $"Capability '{item.CapabilityId}' completes before it starts."));
            }

            foreach (var collector in item.Collectors)
            {
                if (string.IsNullOrWhiteSpace(collector.Id) || string.IsNullOrWhiteSpace(collector.Version))
                {
                    violations.Add(new(
                        "snapshot.coverage.collector-invalid",
                        $"Capability '{item.CapabilityId}' contains an invalid collector identity."));
                }
            }
        }

        foreach (var requested in requestedCapabilities.Distinct(StringComparer.Ordinal))
        {
            if (!capabilityIds.Contains(requested))
            {
                violations.Add(new(
                    "snapshot.coverage.missing",
                    $"Requested capability '{requested}' has no coverage record."));
            }
        }
    }
}

public sealed record SnapshotInvariantViolation(string Code, string Message);
