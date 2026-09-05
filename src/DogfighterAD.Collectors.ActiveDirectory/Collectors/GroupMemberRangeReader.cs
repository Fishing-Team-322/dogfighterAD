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
        if (entry.Attributes.TryGetValue("member", out var completeValues))
        {
            return MemberSegment.CompleteSegment(
                completeValues
                    .Where(value => value.Text is not null)
                    .Select(value => value.Text!)
                    .ToArray());
        }

        var rangedAttributes = entry.Attributes
            .Where(attribute =>
                TryParseRange(attribute.Key, out _, out _, out _))
            .Select(attribute =>
            {
                TryParseRange(attribute.Key, out var start, out var end, out var terminal);
                return new
                {
                    Name = attribute.Key,
                    Start = start,
                    End = end,
                    Terminal = terminal,
                    Values = attribute.Value
                        .Where(value => value.Text is not null)
                        .Select(value => value.Text!)
                        .ToArray()
                };
            })
            .OrderBy(attribute => attribute.Start)
            .ToArray();

        if (rangedAttributes.Length == 0)
        {
            // A group with no direct members legitimately has no member attribute.
            if (expectedStart == 0)
            {
                return MemberSegment.CompleteSegment([]);
            }

            return MemberSegment.Invalid(
                $"LDAP response for '{entry.DistinguishedName}' did not return the requested member range beginning at {expectedStart}.");
        }

        var first = rangedAttributes[0];
        if (first.Start != expectedStart)
        {
            return MemberSegment.Invalid(
                $"LDAP member range for '{entry.DistinguishedName}' began at {first.Start}, expected {expectedStart}.");
        }

        var values = new List<string>();
        var expected = expectedStart;
        var terminalSeen = false;

        foreach (var attribute in rangedAttributes)
        {
            if (attribute.Start != expected)
            {
                return MemberSegment.Invalid(
                    $"LDAP member ranges for '{entry.DistinguishedName}' are not contiguous at index {expected}.");
            }

            values.AddRange(attribute.Values);

            if (attribute.Terminal)
            {
                terminalSeen = true;
                break;
            }

            if (!attribute.End.HasValue || attribute.End.Value < attribute.Start)
            {
                return MemberSegment.Invalid(
                    $"LDAP member range '{attribute.Name}' for '{entry.DistinguishedName}' is invalid.");
            }

            expected = checked(attribute.End.Value + 1);
        }

        return terminalSeen
            ? MemberSegment.CompleteSegment(values)
            : MemberSegment.PartialSegment(values, expected);
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
