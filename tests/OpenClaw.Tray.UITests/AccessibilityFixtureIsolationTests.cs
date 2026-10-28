using System.Diagnostics;

namespace OpenClaw.Tray.UITests;

/// <summary>
/// Pure checks of the child environment the fixture builds. Nothing here starts the app.
/// </summary>
public sealed class AccessibilityFixtureIsolationTests
{
    private static readonly string[] RootVariables =
    [
        "OPENCLAW_TRAY_DATA_DIR",
        "OPENCLAW_TRAY_APPDATA_DIR",
        "OPENCLAW_TRAY_LOCALAPPDATA_DIR",
        "OPENCLAW_TRAY_LOCAL_DATA_DIR",
    ];

    private static string NewRunDirectory()
        => Path.Combine(Path.GetTempPath(), $"OpenClaw.Tray.IsolationTest.{Guid.NewGuid():N}");

    [Fact]
    public void ChildEnvironmentOverridesConflictingInheritedRootsAndLegacyAlias()
    {
        var run = NewRunDirectory();
        try
        {
            var startInfo = new ProcessStartInfo("unused.exe");
            foreach (var name in RootVariables)
                startInfo.Environment[name] = @"C:\Users\real\AppData\inherited-" + name;

            AccessibilityAppFixture.ApplyProfileIsolation(startInfo.Environment, run);

            var env = startInfo.Environment;
            Assert.Equal(run, env["OPENCLAW_TRAY_DATA_DIR"]);
            Assert.Equal(Path.Combine(run, "roaming-root"), env["OPENCLAW_TRAY_APPDATA_DIR"]);
            Assert.Equal(Path.Combine(run, "local-root"), env["OPENCLAW_TRAY_LOCALAPPDATA_DIR"]);
            // The legacy alias is a direct folder and must equal the root plus OpenClawTray.
            Assert.Equal(
                Path.Combine(env["OPENCLAW_TRAY_LOCALAPPDATA_DIR"]!, "OpenClawTray"),
                env["OPENCLAW_TRAY_LOCAL_DATA_DIR"]);
            foreach (var name in RootVariables)
                Assert.StartsWith(run, env[name], StringComparison.OrdinalIgnoreCase);
        }
        finally
        {
            DeleteOwned(run);
        }
    }

    [Fact]
    public void ChildEnvironmentDropsEveryInheritedOpenClawVariable()
    {
        var run = NewRunDirectory();
        try
        {
            var env = new ProcessStartInfo("unused.exe").Environment;
            env["OPENCLAW_STATE_DIR"] = @"C:\Users\real\.openclaw";
            env["openclaw_gateway_fixture"] = "1";
            env["OPENCLAW_GATEWAY_TOKEN"] = "inherited";
            env["UNRELATED_VARIABLE"] = "kept";

            AccessibilityAppFixture.ApplyProfileIsolation(env, run);

            Assert.False(env.ContainsKey("OPENCLAW_STATE_DIR"));
            Assert.False(env.ContainsKey("OPENCLAW_GATEWAY_FIXTURE"));
            Assert.False(env.ContainsKey("OPENCLAW_GATEWAY_TOKEN"));
            Assert.Equal("kept", env["UNRELATED_VARIABLE"]);
            Assert.Equal(run, env["OPENCLAW_TRAY_DATA_DIR"]);
        }
        finally
        {
            DeleteOwned(run);
        }
    }

    [Fact]
    public void TwoRunsReceiveDistinctRootsForEveryVariable()
    {
        var first = NewRunDirectory();
        var second = NewRunDirectory();
        try
        {
            var a = new ProcessStartInfo("unused.exe").Environment;
            var b = new ProcessStartInfo("unused.exe").Environment;
            AccessibilityAppFixture.ApplyProfileIsolation(a, first);
            AccessibilityAppFixture.ApplyProfileIsolation(b, second);

            foreach (var name in RootVariables)
                Assert.NotEqual(a[name], b[name]);
        }
        finally
        {
            DeleteOwned(first);
            DeleteOwned(second);
        }
    }

    [Fact]
    public void FixtureLaunchPathsAllUseTheIsolationHelper()
    {
        var source = File.ReadAllText(Path.Combine(
            FindRepositoryRoot(), "tests", "OpenClaw.Tray.UITests", "AccessibilityAppFixture.cs"));
        Assert.Equal(1, Count(source, "new ProcessStartInfo("));
        Assert.Equal(1, Count(source, "Process.Start("));
        const string call = "ApplyProfileIsolation(startInfo.Environment, _dataDirectory);";
        Assert.Equal(1, Count(source, call));

        // The helper clears inherited OPENCLAW_* variables, so it must run before fixture-specific ones,
        // and nothing outside it may write a profile-root variable.
        var callIndex = source.IndexOf(call, StringComparison.Ordinal);
        var firstFixtureVariable = source.IndexOf("startInfo.Environment[\"OPENCLAW_", StringComparison.Ordinal);
        Assert.True(callIndex < firstFixtureVariable, "Isolation must run before fixture variables are set.");
        Assert.DoesNotContain("Environment[\"OPENCLAW_TRAY_", source.Remove(source.IndexOf("internal static void ApplyProfileIsolation", StringComparison.Ordinal)));
        Assert.DoesNotContain("startInfo.Environment[\"OPENCLAW_TRAY_", source);
    }
    private static int Count(string text, string value)
    {
        var count = 0;
        for (var i = text.IndexOf(value, StringComparison.Ordinal); i >= 0;
             i = text.IndexOf(value, i + value.Length, StringComparison.Ordinal))
            count++;
        return count;
    }

    private static string FindRepositoryRoot()
    {
        var configured = Environment.GetEnvironmentVariable("OPENCLAW_REPO_ROOT");
        if (!string.IsNullOrEmpty(configured)
            && File.Exists(Path.Combine(configured, "tests", "OpenClaw.Tray.UITests", "AccessibilityAppFixture.cs")))
            return configured;
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "build.ps1")))
            dir = dir.Parent;
        return dir?.FullName ?? throw new DirectoryNotFoundException("Repository root not found.");
    }

    // Deletes only the exact directory this test created under the temp folder.
    private static void DeleteOwned(string run)
    {
        if (Directory.Exists(run) && run.StartsWith(Path.GetTempPath(), StringComparison.OrdinalIgnoreCase))
            Directory.Delete(run, recursive: true);
    }
}
