using FrpBan.Client.Services;
using Xunit;

namespace FrpBan.Tests.Services;

public class LineAccumulatorTests
{
    [Fact]
    public void LfAndCrLf_TerminateLinesWithoutTheirSeparators()
    {
        Assert.Equal(["a", "b", ""], Split("a\nb\r\n\n", maxLength: 10));
    }

    [Fact]
    public void OversizedLine_IsDiscardedWholeAndTheNextLineSurvives()
    {
        var oversized = 0;
        Assert.Equal(["ok"], Split("0123456789X\nok\n", maxLength: 10, () => oversized++));
        Assert.Equal(1, oversized);
    }

    [Fact]
    public void CrLfAtExactlyTheLimit_IsAccepted()
    {
        Assert.Equal(["0123456789"], Split("0123456789\r\n", maxLength: 10));
    }

    [Fact]
    public void Flush_ReturnsOnlyAnUnterminatedCompleteFragment()
    {
        var lines = new LineAccumulator(10, () => { });
        foreach (var character in "tail")
            Assert.Null(lines.Append(character));
        Assert.Equal("tail", lines.Flush());
        Assert.Null(lines.Flush());
    }

    [Fact]
    public void Reset_DropsThePartialLine()
    {
        var lines = new LineAccumulator(10, () => { });
        lines.Append('x');
        lines.Reset();
        Assert.Equal("", lines.Append('\n'));
    }

    private static List<string> Split(string text, int maxLength, Action? onOversized = null)
    {
        var lines = new LineAccumulator(maxLength, onOversized ?? (() => { }));
        return text.Select(lines.Append).OfType<string>().ToList();
    }
}
