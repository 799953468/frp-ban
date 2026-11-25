using System.Text;

namespace FrpBan.Client.Services;

/// <summary>
/// Splits a character stream into LF-terminated lines with bounded memory. A trailing CR is removed.
/// Lines longer than the limit are discarded up to their terminating LF, never truncated, so a
/// partial line can never be matched as if it were complete.
/// </summary>
internal sealed class LineAccumulator(int maxLength, Action onOversizedLine)
{
    private readonly StringBuilder _line = new();
    private bool _discarding;

    /// <summary>Appends one character; returns the completed line when it is a LF, otherwise null.</summary>
    public string? Append(char character)
    {
        if (character == '\n')
        {
            string? line = null;
            if (!_discarding)
            {
                if (_line.Length > 0 && _line[^1] == '\r')
                    _line.Length--;
                line = _line.ToString();
            }

            _line.Clear();
            _discarding = false;
            return line;
        }

        if (_discarding)
            return null;

        // Allow the CR of a CRLF at exactly the limit; it is removed when the LF arrives.
        if (_line.Length >= maxLength && !(_line.Length == maxLength && character == '\r'))
        {
            _line.Clear();
            _discarding = true;
            onOversizedLine();
            return null;
        }

        _line.Append(character);
        return null;
    }

    /// <summary>Returns an unterminated final line, if any, and resets.</summary>
    public string? Flush()
    {
        var line = _discarding || _line.Length == 0 ? null : _line.ToString();
        Reset();
        return line;
    }

    /// <summary>Drops any partial line, e.g. after the underlying file was replaced.</summary>
    public void Reset()
    {
        _line.Clear();
        _discarding = false;
    }
}
