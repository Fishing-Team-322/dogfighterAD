using System.Net;
using DogfighterAD.Application.Collection;
using DogfighterAD.Cli;
using DogfighterAD.Collectors.ActiveDirectory.Sysvol;

namespace DogfighterAD.Core.Tests.Cli;

public sealed class ProductionCompositionTests
{
    [Theory]
    [InlineData("minimal", 5, 8)]
    [InlineData("audit-full", 9, 12)]
    public void BuiltInProfile_SchedulesEachProductionCollectorOnce(string name, int collectorCount, int capabilityCount)
    {
        Assert.True(BuiltInCollectionProfiles.TryGet(name, out var profile));
        var registry = CollectionComposition.CreateCollectors(new ScanCommand
        {
            Target = "dc.mini.lab", OutputPath = "unused.dogad", Profile = name
        });
        var plan = new CollectionPlanner().BuildPlan(profile, registry);
        var scheduled = plan.Stages.SelectMany(stage => stage.Collectors).ToArray();
        Assert.Equal(collectorCount, scheduled.Length);
        Assert.Equal(collectorCount, scheduled.Select(item => item.Collector.Id).Distinct().Count());
        Assert.Equal(capabilityCount, scheduled.SelectMany(item => item.SelectedCapabilities).Count());
        Assert.Equal(profile.RequestedCapabilities.Order(), plan.EffectiveCapabilities.Order());
        Assert.Contains(scheduled, item => item.SelectedCapabilities.Count == 4);
    }

    [Fact]
    public void SysvolFactory_UsesOsContextWithoutExplicitCredential()
    {
        var command = new ScanCommand
        {
            Target = "dc.mini.lab",
            OutputPath = "unused.dogad",
            Profile = "audit-full"
        };

        var factory = CollectionComposition.CreateSysvolFactory(command, credential: null);

        Assert.IsType<SystemSysvolClientFactory>(factory);
    }

    [Fact]
    public void SysvolFactory_UsesPortableKerberosWithExplicitCredential()
    {
        var command = new ScanCommand
        {
            Target = "dc.mini.lab",
            OutputPath = "unused.dogad",
            Profile = "audit-full"
        };
        var credential = new NetworkCredential("alice", "test-only-password", "MINILAB");

        var factory = CollectionComposition.CreateSysvolFactory(command, credential);

        Assert.IsType<PortableKerberosSysvolClientFactory>(factory);
    }

    [Fact]
    public void SysvolFactory_RejectsIpTargetForPortableKerberos()
    {
        var command = new ScanCommand
        {
            Target = "192.168.57.30",
            OutputPath = "unused.dogad",
            Profile = "audit-full"
        };
        var credential = new NetworkCredential("alice", "test-only-password", "MINILAB");

        var exception = Assert.Throws<ArgumentException>(() =>
            CollectionComposition.CreateSysvolFactory(command, credential));

        Assert.Contains("DNS", exception.Message, StringComparison.OrdinalIgnoreCase);
    }
}
