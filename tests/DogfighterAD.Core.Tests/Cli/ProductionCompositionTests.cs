using DogfighterAD.Application.Collection;
using DogfighterAD.Cli;

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
}
