using OpenClawTray.Helpers;
using OpenClawTray.Services;
using System;
using System.Drawing;
using System.Drawing.Imaging;
using System.IO;
using System.Runtime.Versioning;
using Xunit;

namespace OpenClaw.Tray.Tests;

/// <summary>
/// Verifies the lobster tray/desktop icon badge policy: only attention states are
/// badged (grey dot for disconnected, red dot with a "-" for error); healthy
/// states (connected/connecting) render the plain lobster with no badge.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class StatusBadgeIconFactoryTests
{
    [Theory]
    [InlineData((int)ConnectionStatusAccent.Success, 76, 175, 80)]
    [InlineData((int)ConnectionStatusAccent.Caution, 255, 193, 7)]
    [InlineData((int)ConnectionStatusAccent.Critical, 244, 67, 54)]
    [InlineData((int)ConnectionStatusAccent.Neutral, 158, 158, 158)]
    public void DotColor_MapsAccentToStatusColor(int accent, int r, int g, int b)
    {
        var color = StatusBadgeIconFactory.DotColor((ConnectionStatusAccent)accent);
        Assert.Equal(Color.FromArgb(r, g, b), color);
    }

    [Theory]
    [InlineData((int)ConnectionStatusAccent.Neutral, true)]
    [InlineData((int)ConnectionStatusAccent.Critical, true)]
    [InlineData((int)ConnectionStatusAccent.Success, false)]
    [InlineData((int)ConnectionStatusAccent.Caution, false)]
    public void ShouldBadge_OnlyNeutralAndCritical(int accent, bool expected)
    {
        Assert.Equal(expected, StatusBadgeIconFactory.ShouldBadge((ConnectionStatusAccent)accent));
    }

    [Theory]
    [InlineData((int)ConnectionStatusAccent.Critical, true)]
    [InlineData((int)ConnectionStatusAccent.Neutral, false)]
    [InlineData((int)ConnectionStatusAccent.Success, false)]
    [InlineData((int)ConnectionStatusAccent.Caution, false)]
    public void HasDash_OnlyCritical(int accent, bool expected)
    {
        Assert.Equal(expected, StatusBadgeIconFactory.HasDash((ConnectionStatusAccent)accent));
    }

    [Fact]
    public void Compose_DrawsDotInBottomRightCorner()
    {
        const int size = 64;
        using var baseImage = new Bitmap(size, size, PixelFormat.Format32bppArgb);
        // Fully transparent base so the only opaque pixels come from the dot.

        using var composed = StatusBadgeIconFactory.Compose(
            baseImage, size, StatusBadgeIconFactory.DotColor(ConnectionStatusAccent.Neutral));

        // Bottom-right region carries the dot.
        var dotPixel = composed.GetPixel((int)(size * 0.80), (int)(size * 0.80));
        Assert.True(dotPixel.A > 200, "Dot should be opaque in the bottom-right corner");

        // Top-left stays transparent (no badge, base was empty).
        var cornerPixel = composed.GetPixel(2, 2);
        Assert.True(cornerPixel.A < 40, "Top-left corner should remain transparent");
    }

    [Fact]
    public void Compose_NullColor_RendersPlainLobsterWithNoBadge()
    {
        const int size = 64;
        using var baseImage = new Bitmap(size, size, PixelFormat.Format32bppArgb);
        // Transparent base + null dot colour => the whole icon stays transparent.

        using var composed = StatusBadgeIconFactory.Compose(baseImage, size, dotColor: null);

        var dotPixel = composed.GetPixel((int)(size * 0.80), (int)(size * 0.80));
        Assert.True(dotPixel.A < 40, "Healthy state should render no dot in the bottom-right corner");
    }

    [Fact]
    public void Compose_ErrorState_DrawsRedDotWithWhiteDash()
    {
        const int size = 64;
        using var baseImage = new Bitmap(size, size, PixelFormat.Format32bppArgb);

        using var composed = StatusBadgeIconFactory.Compose(
            baseImage, size, StatusBadgeIconFactory.DotColor(ConnectionStatusAccent.Critical), withDash: true);

        var (cx, cy, dot) = DotCenter(size);

        // Centre of the dot is covered by the white minus glyph.
        var centre = composed.GetPixel((int)cx, (int)cy);
        Assert.True(centre.R > 230 && centre.G > 230 && centre.B > 230, "Dash centre should be white");

        // Below the dash (still inside the dot) reads red.
        var belowDash = composed.GetPixel((int)cx, (int)(cy + dot * 0.30f));
        Assert.True(belowDash.A > 200 && belowDash.R > belowDash.G && belowDash.R > belowDash.B,
            "Dot around the dash should read red");
    }

    [Fact]
    public void Compose_UsesDistinctColorPerAccent()
    {
        const int size = 64;
        using var baseImage = new Bitmap(size, size, PixelFormat.Format32bppArgb);
        var px = (int)(size * 0.80);

        using var neutral = StatusBadgeIconFactory.Compose(baseImage, size, StatusBadgeIconFactory.DotColor(ConnectionStatusAccent.Neutral));
        using var critical = StatusBadgeIconFactory.Compose(baseImage, size, StatusBadgeIconFactory.DotColor(ConnectionStatusAccent.Critical));

        var gray = neutral.GetPixel(px, px);
        var red = critical.GetPixel(px, px);
        Assert.True(Math.Abs(gray.R - gray.G) < 20 && Math.Abs(gray.G - gray.B) < 20, "Neutral dot is grey");
        Assert.True(red.R > red.G && red.R > red.B, "Critical dot is red-dominant");
    }

    [Fact]
    public void DotFraction_ScalesLargerOnTinyIconsAndSubtlerOnLargeIcons()
    {
        // Tiny tray icons get the largest dot for legibility.
        Assert.Equal(0.44, StatusBadgeIconFactory.DotFraction(16), 3);
        Assert.Equal(0.44, StatusBadgeIconFactory.DotFraction(32), 3);

        // Large taskbar / alt-tab icons get the subtlest dot.
        Assert.Equal(0.26, StatusBadgeIconFactory.DotFraction(256), 3);

        // Monotonically shrinks as the icon grows between the two extremes.
        var f48 = StatusBadgeIconFactory.DotFraction(48);
        var f128 = StatusBadgeIconFactory.DotFraction(128);
        Assert.True(f48 < 0.44 && f48 > f128, "48px dot fraction sits between the extremes");
        Assert.True(f128 > 0.26 && f128 < f48, "128px dot fraction is subtler than 48px but above the floor");
    }

    [Fact]
    public void CreateIcoBytes_ProducesValidMultiSizeIcon()
    {
        var sizes = new[] { 16, 32, 48 };
        using var baseImage = new Bitmap(256, 256, PixelFormat.Format32bppArgb);

        var bytes = StatusBadgeIconFactory.CreateIcoBytes(
            baseImage, StatusBadgeIconFactory.DotColor(ConnectionStatusAccent.Critical), withDash: true, sizes);

        // ICONDIR header: reserved=0, type=1 (icon), count=frames.
        Assert.Equal(0, bytes[0] | bytes[1]);
        Assert.Equal(1, bytes[2] | (bytes[3] << 8));
        var count = bytes[4] | (bytes[5] << 8);
        Assert.Equal(sizes.Length, count);

        // The container round-trips back into a real icon.
        using var stream = new MemoryStream(bytes);
        using var icon = new Icon(stream);
        Assert.NotNull(icon);
    }

    [Fact]
    public void CreateIcoBytes_NullColor_ProducesValidPlainIcon()
    {
        var sizes = new[] { 16, 32 };
        using var baseImage = new Bitmap(256, 256, PixelFormat.Format32bppArgb);

        var bytes = StatusBadgeIconFactory.CreateIcoBytes(baseImage, dotColor: null, withDash: false, sizes);

        using var stream = new MemoryStream(bytes);
        using var icon = new Icon(stream);
        Assert.NotNull(icon);
    }

    [Fact]
    public void IconSizes_CoverTrayAndTaskbarResolutions()
    {
        Assert.Contains(16, StatusBadgeIconFactory.IconSizes);   // tray at 100% DPI
        Assert.Contains(32, StatusBadgeIconFactory.IconSizes);   // tray at 200% DPI / taskbar
        Assert.Contains(256, StatusBadgeIconFactory.IconSizes);  // high-DPI taskbar
    }

    // Mirrors the dot geometry in StatusBadgeIconFactory.Compose so tests can sample
    // the dot centre precisely.
    private static (float Cx, float Cy, float Dot) DotCenter(int size)
    {
        float dot = size * (float)StatusBadgeIconFactory.DotFraction(size);
        float ring = Math.Max(1f, dot * 0.14f);
        float pad = size * 0.02f;
        float outer = dot + (ring * 2f);
        float outerX = size - outer - pad;
        float outerY = size - outer - pad;
        return (outerX + ring + (dot / 2f), outerY + ring + (dot / 2f), dot);
    }
}
