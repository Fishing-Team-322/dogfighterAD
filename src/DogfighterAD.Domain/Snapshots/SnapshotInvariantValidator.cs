namespace DogfighterAD.Domain.Snapshots;

public static class SnapshotInvariantValidator
{
    public static IReadOnlyList<SnapshotInvariantViolation> Validate(AdSnapshot snapshot)
    {
        ArgumentNullException.ThrowIfNull(snapshot);

        // JSON required/non-null annotations are compile-time contracts, not a complete validation
        // boundary for untrusted artifacts. Structural validation must run before any semantic code
        // dereferences nested objects or canonicalizes collections.
        var structuralViolations = SnapshotStructuralValidator.Validate(snapshot);
        if (structuralViolations.Count > 0)
        {
            return structuralViolations;
        }

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

        if (string.IsNullOrWhiteSpace(snapshot.Metadata.ProductVersion) ||
            snapshot.Metadata.RequestedCapabilities.Any(string.IsNullOrWhiteSpace))
        {
            violations.Add(new("snapshot.metadata.invalid", "Product version and requested capability identifiers must be nonempty."));
        }
        if (!Enum.IsDefined(snapshot.Metadata.CompletionStatus))
            violations.Add(new("snapshot.status.invalid", "Snapshot completion status is not defined."));
        foreach (var item in snapshot.Coverage)
        {
            if (!Enum.IsDefined(item.Status) || item.ObservedItemCount < 0 ||
                item.Issues.Any(issue => !Enum.IsDefined(issue.Severity)))
                violations.Add(new("snapshot.coverage.invalid", "Coverage contains an undefined status/severity or a negative count."));
        }
        foreach (var fact in snapshot.Observations)
        {
            if (!Enum.IsDefined(fact.Disposition) || !Enum.IsDefined(fact.ValueKind))
                violations.Add(new("snapshot.fact.enum-invalid", "Observed fact has an undefined disposition or value kind."));
        }
        foreach (var setting in snapshot.Content.GroupPolicySettings)
        {
            if (!Enum.IsDefined(setting.Disposition) || !Enum.IsDefined(setting.ValueKind) ||
                !Enum.IsDefined(setting.Kind) || !Enum.IsDefined(setting.Scope))
                violations.Add(new("snapshot.gpo-setting.enum-invalid", "GPO setting contains an undefined enumeration value."));
        }
        if (snapshot.Content.Aces.Any(ace => !Enum.IsDefined(ace.AccessType)) ||
            snapshot.Content.SecurityDescriptors.Any(item => !Enum.IsDefined(item.DaclState)) ||
            snapshot.Content.GroupPolicyFiles.Any(item => !Enum.IsDefined(item.Kind)) ||
            snapshot.Content.GroupMemberships.Any(item => !Enum.IsDefined(item.Source)))
            violations.Add(new("snapshot.content.enum-invalid", "Snapshot content contains an undefined enumeration value."));

        ValidateDirectoryObjectIdentities(snapshot.Content, violations);
        ValidateRelationships(snapshot.Content, violations);
        ValidateObservations(snapshot.Observations, violations);
        ValidateCoverage(snapshot.Coverage, snapshot.Metadata.RequestedCapabilities, violations);

        var calculatedStatus = SnapshotCompletionStatusCalculator.Calculate(
            snapshot.Metadata.RequestedCapabilities,
            snapshot.Coverage);
        if (snapshot.Metadata.CompletionStatus != calculatedStatus)
        {
            violations.Add(new(
                "snapshot.completion-status.inconsistent",
                $"Snapshot completion status {snapshot.Metadata.CompletionStatus} does not match requested capability coverage ({calculatedStatus})."));
        }

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

        var linkOrders = new HashSet<(AdObjectId ContainerId, int Order)>();
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

            if (link.Order < 1)
            {
                violations.Add(new(
                    "snapshot.gpo-link.invalid-order",
                    $"GPO link for container {link.ContainerId} has invalid order {link.Order}."));
            }
            else if (!linkOrders.Add((link.ContainerId, link.Order)))
            {
                violations.Add(new(
                    "snapshot.gpo-link.duplicate-order",
                    $"Container {link.ContainerId} has more than one GPO link at order {link.Order}."));
            }

            if (link.RawOptions < 0)
            {
                violations.Add(new(
                    "snapshot.gpo-link.invalid-options",
                    $"GPO link for container {link.ContainerId} has negative raw options {link.RawOptions}."));
            }
        }

        var gpoContainerPolicyTargets = new HashSet<AdObjectId>();
        foreach (var policy in content.GroupPolicyContainerPolicies)
        {
            if (!knownObjectIds.Contains(policy.ContainerId))
            {
                violations.Add(new(
                    "snapshot.gpo-container-policy.unknown-container",
                    $"GPO inheritance state references unknown container {policy.ContainerId}."));
            }

            if (!gpoContainerPolicyTargets.Add(policy.ContainerId))
            {
                violations.Add(new(
                    "snapshot.gpo-container-policy.duplicate-container",
                    $"GPO inheritance state for container {policy.ContainerId} appears more than once."));
            }

            if (policy.RawOptions < 0)
            {
                violations.Add(new(
                    "snapshot.gpo-container-policy.invalid-options",
                    $"GPO inheritance state for container {policy.ContainerId} has negative raw options {policy.RawOptions}."));
            }
        }

        ValidateGpoSysvol(content, knownGpoIds, violations);

        var descriptorTargets = new HashSet<AdObjectId>();
        foreach (var descriptor in content.SecurityDescriptors)
        {
            if (!knownObjectIds.Contains(descriptor.TargetObjectId))
            {
                violations.Add(new(
                    "snapshot.security-descriptor.unknown-target",
                    $"Security descriptor references unknown target object {descriptor.TargetObjectId}."));
            }

            if (!descriptorTargets.Add(descriptor.TargetObjectId))
            {
                violations.Add(new(
                    "snapshot.security-descriptor.duplicate-target",
                    $"Security descriptor for target {descriptor.TargetObjectId} appears more than once."));
            }
        }

        var acePositions = new HashSet<(AdObjectId TargetObjectId, int AceIndex)>();
        foreach (var ace in content.Aces)
        {
            if (!knownObjectIds.Contains(ace.TargetObjectId))
            {
                violations.Add(new(
                    "snapshot.ace.unknown-target",
                    $"ACE references unknown target object {ace.TargetObjectId}."));
            }

            if (ace.AceIndex < 0)
            {
                violations.Add(new(
                    "snapshot.ace.invalid-index",
                    $"ACE for target {ace.TargetObjectId} has negative source index {ace.AceIndex}."));
            }
            else if (!acePositions.Add((ace.TargetObjectId, ace.AceIndex)))
            {
                violations.Add(new(
                    "snapshot.ace.duplicate-index",
                    $"Target {ace.TargetObjectId} contains more than one typed ACE at source index {ace.AceIndex}."));
            }

            if (string.IsNullOrWhiteSpace(ace.TrusteeSid))
            {
                violations.Add(new(
                    "snapshot.ace.missing-trustee",
                    $"ACE for target {ace.TargetObjectId} has no trustee SID."));
            }
        }
    }

    private static void ValidateGpoSysvol(
        SnapshotContent content,
        IReadOnlySet<AdObjectId> knownGpoIds,
        ICollection<SnapshotInvariantViolation> violations)
    {
        var fileKeys = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var file in content.GroupPolicyFiles)
        {
            if (!knownGpoIds.Contains(file.GpoId))
            {
                violations.Add(new(
                    "snapshot.gpo-sysvol-file.unknown-gpo",
                    $"SYSVOL file '{file.RelativePath}' references unknown GPO {file.GpoId}."));
            }

            if (string.IsNullOrWhiteSpace(file.RelativePath) || file.RelativePath.StartsWith("..", StringComparison.Ordinal))
            {
                violations.Add(new(
                    "snapshot.gpo-sysvol-file.invalid-path",
                    $"SYSVOL file for GPO {file.GpoId} has an invalid relative path."));
            }

            if (file.Length < 0)
            {
                violations.Add(new(
                    "snapshot.gpo-sysvol-file.invalid-length",
                    $"SYSVOL file '{file.RelativePath}' for GPO {file.GpoId} has negative length {file.Length}."));
            }

            if (file.Sha256 is not null &&
                (file.Sha256.Length != 64 || file.Sha256.Any(character => !Uri.IsHexDigit(character))))
            {
                violations.Add(new(
                    "snapshot.gpo-sysvol-file.invalid-hash",
                    $"SYSVOL file '{file.RelativePath}' for GPO {file.GpoId} has an invalid SHA-256 value."));
            }

            if (!fileKeys.Add($"{file.GpoId}|{file.RelativePath}"))
            {
                violations.Add(new(
                    "snapshot.gpo-sysvol-file.duplicate",
                    $"SYSVOL file '{file.RelativePath}' for GPO {file.GpoId} appears more than once."));
            }
        }

        foreach (var setting in content.GroupPolicySettings)
        {
            if (!knownGpoIds.Contains(setting.GpoId))
            {
                violations.Add(new(
                    "snapshot.gpo-setting.unknown-gpo",
                    $"GPO setting '{setting.Key}' references unknown GPO {setting.GpoId}."));
            }

            if (setting.Sequence < 1 || string.IsNullOrWhiteSpace(setting.SourceRelativePath) || string.IsNullOrWhiteSpace(setting.Key))
            {
                violations.Add(new(
                    "snapshot.gpo-setting.identity-invalid",
                    $"GPO setting for {setting.GpoId} has invalid source/sequence/key identity."));
            }

            if (setting.DataLength < 0)
            {
                violations.Add(new(
                    "snapshot.gpo-setting.invalid-data-length",
                    $"GPO setting '{setting.Key}' for {setting.GpoId} has negative data length {setting.DataLength}."));
            }

            if ((setting.Disposition is FactDisposition.Redacted or FactDisposition.MetadataOnly) &&
                setting.Value is not null)
            {
                violations.Add(new(
                    "snapshot.gpo-setting.redaction-invalid",
                    $"GPO setting '{setting.Key}' for {setting.GpoId} is {setting.Disposition} but still contains a value."));
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

            if (item.ContractVersion < 1)
            {
                violations.Add(new(
                    "snapshot.coverage.invalid-contract-version",
                    $"Capability '{item.CapabilityId}' has invalid contract version {item.ContractVersion}."));
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
