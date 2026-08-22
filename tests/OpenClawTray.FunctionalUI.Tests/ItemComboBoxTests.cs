using OpenClawTray.FunctionalUI.Core;
using static OpenClawTray.FunctionalUI.Factories;

namespace OpenClawTray.FunctionalUI.Tests;

public sealed class ItemComboBoxTests
{
    [Fact]
    public void ComboBox_ItemsOverload_CapturesItemsSelectionAndCallback()
    {
        string? changed = null;
        var items = new List<ComboItem>
        {
            new("a", "Alpha"),
            new("b", "Beta"),
        };

        var element = ComboBox(items, "b", id => changed = id);

        Assert.Same(items, element.Items);
        Assert.Equal("b", element.SelectedId);
        element.OnSelectionChanged!("a");
        Assert.Equal("a", changed);
    }

    [Fact]
    public void ComboItem_DefaultsAreNormalSelectableRow()
    {
        var item = new ComboItem("id", "Label");

        Assert.True(item.Enabled);
        Assert.False(item.IsHeader);
        Assert.Equal(0, item.Indent);
    }

    [Fact]
    public void ItemsEqual_ReturnsTrue_ForEquivalentLists()
    {
        var left = new List<ComboItem>
        {
            new("", "Group", Enabled: false, IsHeader: true),
            new("one", "First", Indent: 8),
        };
        var right = new List<ComboItem>
        {
            new("", "Group", Enabled: false, IsHeader: true),
            new("one", "First", Indent: 8),
        };

        Assert.True(ItemComboBoxElement.ItemsEqual(left, right));
    }

    [Fact]
    public void ItemsEqual_DetectsLabelOrderAndFlagChanges()
    {
        var baseline = new List<ComboItem> { new("one", "First"), new("two", "Second") };

        Assert.False(ItemComboBoxElement.ItemsEqual(baseline,
            new List<ComboItem> { new("one", "Renamed"), new("two", "Second") }));
        Assert.False(ItemComboBoxElement.ItemsEqual(baseline,
            new List<ComboItem> { new("two", "Second"), new("one", "First") }));
        Assert.False(ItemComboBoxElement.ItemsEqual(baseline,
            new List<ComboItem> { new("one", "First", Enabled: false), new("two", "Second") }));
        Assert.False(ItemComboBoxElement.ItemsEqual(baseline,
            new List<ComboItem> { new("one", "First") }));
    }

    [Fact]
    public void ItemsEqual_HandlesReferenceEqualAndEmpty()
    {
        var list = new List<ComboItem> { new("one", "First") };

        Assert.True(ItemComboBoxElement.ItemsEqual(list, list));
        Assert.True(ItemComboBoxElement.ItemsEqual(new List<ComboItem>(), new List<ComboItem>()));
    }
}
