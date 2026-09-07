using DogfighterAD.Collectors.ActiveDirectory.Ldap;

namespace DogfighterAD.Collectors.ActiveDirectory.Collectors;

internal sealed class GroupMemberRangeReader
{
    public async Task<MemberRangeReadResult> ReadAsync(
        IReadOnlyLdapClient client,
        LdapSearchEntry initialEntry,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(client);
        ArgumentNullException.ThrowIfNull(initialEntry);

        var members = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var initial = ReadMemberSegment(initialEntry, expectedStart: 0);
        if (!initial.Valid)
        {
            return MemberRangeReadResult.Failed(initial.Error!);
        }

        foreach (var member in initial.Values)
        {
            members.Add(member);
        }

        if (initial.Complete)
        {
            return MemberRangeReadResult.Succeeded(Sort(members));
        }

        var nextStart = initial.NextStart!.Value;

        while (true)
        {
            cancellationToken.ThrowIfCancellationRequested();

            var response = await client.SearchAsync(
                new LdapSearchRequest
                {
                    BaseDn = initialEntry.DistinguishedName,
                    Filter = "(objectClass=*)",
                    Scope = LdapSearchScope.Base,
                    Attributes = [$"member;range={nextStart}-*"]
                },
                cancellationToken).ConfigureAwait(false);

            if (response.Entries.Count != 1)
            {
                return MemberRangeReadResult.Partial(
                    Sort(members),
                    $"Membership range request for '{initialEntry.DistinguishedName}' returned {response.Entries.Count} entries; exactly one was expected.");
            }

            var segment = ReadMemberSegment(response.Entries[0], nextStart);
            if (!segment.Valid)
            {
                return MemberRangeReadResult.Partial(Sort(members), segment.Error!);
            }

            foreach (var member in segment.Values)
            {
                members.Add(member);
            }

            if (segment.Complete)
            {
                return MemberRangeReadResult.Succeeded(Sort(members));
            }

            if (!segment.NextStart.HasValue || segment.NextStart.Value <= nextStart)
            {
                return MemberRangeReadResult.Partial(
                    Sort(members),
                    $"Membership range for '{initialEntry.DistinguishedName}' did not advance beyond index {nextStart}.");
            }

            nextStart = segment.NextStart.Value;
        }
    }

    private static MemberSegment ReadMemberSegment(
        LdapSearchEntry entry,
        int expectedStart)
    {
        var rangeNamedAttributes = entry.Attributes
            .Where(attribute => attribute.Key.StartsWith(
                "member;range=",
                StringComparison.OrdinalIgnoreCase))
            .ToArray();

        if (rangeNamedAttributes.Length > 0)
        {
            var parsedRanges = new List<RangeAttribute>(rangeNamedAttributes.Length);
            foreach (var attribute in rangeNamedAttributes)
            {
                if (!TryParseRange(attribute.Key, out var start, out var end, out var terminal))
                {
                    return MemberSegment.Invalid(
                        $"LDAP response for '{entry.DistinguishedName}' returned malformed member range '{attribute.Key}'.");
                }

                parsedRanges.Add(new RangeAttribute(
                    attribute.Key,
                    start,
                    end,
                    terminal,
                    attribute.Value
                        .Where(value => value.Text is not null)
                        .Select(value => value.Text!)
                        .ToArray()));
            }

            var normalizedRanges = new List<RangeAttribute>();
            foreach (var group in parsedRanges
                         .GroupBy(attribute => attribute.Start)
                         .OrderBy(group => group.Key))
            {
                // AD can echo an empty requested member;range=N-* placeholder together with the
                // actual member;range=N-M attribute. Such a placeholder must not be interpreted as
                // the terminal range when a substantive range for the same start is present.
                var substantive = group
                    .Where(attribute => attribute.Values.Count > 0 || !attribute.Terminal)
                    .ToArray();

                if (substantive.Length > 1)
                {
                    return MemberSegment.Invalid(
                        $"LDAP response for '{entry.DistinguishedName}' returned ambiguous member ranges beginning at {group.Key}.");
                }

                RangeAttribute selected;
                if (substantive.Length == 1)
                {
                    selected = substantive[0];
                    if (group.Any(attribute =>
                            !ReferenceEquals(attribute, selected) &&
                            (attribute.Values.Count > 0 || !attribute.Terminal)))
                    {
                        return MemberSegment.Invalid(
                            $"LDAP response for '{entry.DistinguishedName}' returned conflicting member ranges beginning at {group.Key}.");
                    }
                }
                else
                {
                    var placeholders = group.ToArray();
                    if (placeholders.Any(attribute => !attribute.Terminal) ||
                        placeholders.Any(attribute => attribute.Values.Count > 0))
                    {
                        return MemberSegment.Invalid(
                            $"LDAP response for '{entry.DistinguishedName}' returned an invalid empty member range beginning at {group.Key}.");
                    }

                    selected = placeholders[0];
                }

                normalizedRanges.Add(selected);
            }

            if (normalizedRanges.Count == 0 || normalizedRanges[0].Start != expectedStart)
            {
                var actual = normalizedRanges.Count == 0 ? "none" : normalizedRanges[0].Start.ToString();
                return MemberSegment.Invalid(
                    $"LDAP member range for '{entry.DistinguishedName}' began at {actual}, expected {expectedStart}.");
            }

            var values = new List<string>();
            var expected = expectedStart;

            for (var index = 0; index < normalizedRanges.Count; index++)
            {
                var attribute = normalizedRanges[index];
                if (attribute.Start != expected)
                {
                    return MemberSegment.Invalid(
                        $"LDAP member ranges for '{entry.DistinguishedName}' are not contiguous at index {expected}.");
                }

                values.AddRange(attribute.Values);

                if (attribute.Terminal)
                {
                    if (index != normalizedRanges.Count - 1)
                    {
                        return MemberSegment.Invalid(
                            $"LDAP member range '{attribute.Name}' for '{entry.DistinguishedName}' is terminal but additional ranges were returned.");
                    }

                    return MemberSegment.CompleteSegment(values);
                }

                if (!attribute.End.HasValue || attribute.End.Value < attribute.Start)
                {
                    return MemberSegment.Invalid(
                        $"LDAP member range '{attribute.Name}' for '{entry.DistinguishedName}' is invalid.");
                }

                var declaredCount = checked(attribute.End.Value - attribute.Start + 1);
                if (attribute.Values.Count != declaredCount)
                {
                    return MemberSegment.Invalid(
                        $"LDAP member range '{attribute.Name}' for '{entry.DistinguishedName}' returned {attribute.Values.Count} value(s), expected {declaredCount}.");
                }

                expected = checked(attribute.End.Value + 1);
            }

            return MemberSegment.PartialSegment(values, expected);
        }

        if (entry.Attributes.TryGetValue("member", out var completeValues))
        {
            return MemberSegment.CompleteSegment(
                completeValues
                    .Where(value => value.Text is not null)
                    .Select(value => value.Text!)
                    .ToArray());
        }

        // A group with no direct members legitimately has no member attribute on the initial read.
        if (expectedStart == 0)
        {
            return MemberSegment.CompleteSegment([]);
        }

        return MemberSegment.Invalid(
            $"LDAP response for '{entry.DistinguishedName}' did not return the requested member range beginning at {expectedStart}.");
    }

    private static bool TryParseRange(
        string attributeName,
        out int start,
        out int? end,
        out bool terminal)
    {
        const string prefix = "member;range=";
        start = 0;
        end = null;
        terminal = false;

        if (!attributeName.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        var range = attributeName[prefix.Length..];
        var separator = range.IndexOf('-');
        if (separator <= 0 || separator == range.Length - 1)
        {
            return false;
        }

        if (!int.TryParse(range[..separator], out start) || start < 0)
        {
            return false;
        }

        var endText = range[(separator + 1)..];
        if (endText == "*")
        {
            terminal = true;
            return true;
        }

        if (!int.TryParse(endText, out var parsedEnd) || parsedEnd < start)
        {
            return false;
        }

        end = parsedEnd;
        return true;
    }

    private static IReadOnlyList<string> Sort(IEnumerable<string> members) =>
        members
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .OrderBy(member => member, StringComparer.OrdinalIgnoreCase)
            .ToArray();

    private sealed record RangeAttribute(
        string Name,
        int Start,
        int? End,
        bool Terminal,
        IReadOnlyList<string> Values);

    private sealed record MemberSegment(
        bool Valid,
        bool Complete,
        IReadOnlyList<string> Values,
        int? NextStart,
        string? Error)
    {
        public static MemberSegment CompleteSegment(IReadOnlyList<string> values) =>
            new(true, true, values, null, null);

        public static MemberSegment PartialSegment(IReadOnlyList<string> values, int nextStart) =>
            new(true, false, values, nextStart, null);

        public static MemberSegment Invalid(string error) =>
            new(false, false, [], null, error);
    }
}

internal sealed record MemberRangeReadResult(
    IReadOnlyList<string> Members,
    bool Complete,
    string? Error)
{
    public static MemberRangeReadResult Succeeded(IReadOnlyList<string> members) =>
        new(members, true, null);

    public static MemberRangeReadResult Partial(IReadOnlyList<string> members, string error) =>
        new(members, false, error);

    public static MemberRangeReadResult Failed(string error) =>
        new([], false, error);
}
