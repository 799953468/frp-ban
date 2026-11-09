using FrpBan.Client.Configuration;
using FrpBan.Client.Services;
using Microsoft.Extensions.Logging;
using Moq;
using Xunit;

namespace FrpBan.Tests.Services;

public class RuleMatchEngineTests
{
    private readonly Mock<ILogger<RuleMatchEngine>> _loggerMock;

    public RuleMatchEngineTests()
    {
        _loggerMock = new Mock<ILogger<RuleMatchEngine>>();
    }

    [Fact]
    public void ProcessLogLine_WithDisabledRule_ReturnsEmptyList()
    {
        // Arrange
        var engine = new RuleMatchEngine(_loggerMock.Object);
        var rule = new BanRule
        {
            Enabled = false,
            Name = "Test Rule",
            Matching = new List<MatchExpression>()
        };

        // Act
        var result = engine.ProcessLogLine("2024-01-01 10:00:00 192.168.1.1 failed", rule);

        // Assert
        Assert.Empty(result);
    }

    [Fact]
    public void ProcessLogLine_WithRegexMatch_ExtractsIp()
    {
        // Arrange
        var engine = new RuleMatchEngine(_loggerMock.Object);
        var rule = new BanRule
        {
            Enabled = true,
            Name = "Failed Login",
            Matching = new List<MatchExpression>
            {
                new MatchExpression
                {
                    Type = "regex",
                    Pattern = @"Failed login from (?<ip>\d+\.\d+\.\d+\.\d+)"
                }
            },
            Action = new BanAction
            {
                Type = "immediate",
                Reason = "Failed login",
                BanDurationSeconds = 3600
            }
        };

        // Act
        var result = engine.ProcessLogLine("Failed login from 192.168.1.1", rule);

        // Assert
        Assert.Single(result);
        Assert.Equal("192.168.1.1", result[0].ip);
        Assert.Equal("Failed login", result[0].reason);
        Assert.Equal(3600, result[0].durationSeconds);
    }

    [Fact]
    public void ProcessLogLine_WithJsonMatch_ExtractsIp()
    {
        // Arrange
        var engine = new RuleMatchEngine(_loggerMock.Object);
        var rule = new BanRule
        {
            Enabled = true,
            Name = "JSON Log",
            Matching = new List<MatchExpression>
            {
                new MatchExpression
                {
                    Type = "json",
                    JsonPath = "source_ip"
                }
            },
            Action = new BanAction
            {
                Type = "immediate",
                Reason = "Suspicious activity",
                BanDurationSeconds = 7200
            }
        };

        var logLine = @"{""timestamp"":""2024-01-01T10:00:00Z"",""source_ip"":""10.0.0.1"",""event"":""attack""}";

        // Act
        var result = engine.ProcessLogLine(logLine, rule);

        // Assert
        Assert.Single(result);
        Assert.Equal("10.0.0.1", result[0].ip);
    }

    [Fact]
    public void ProcessLogLine_WithThresholdAction_BansAfterThreshold()
    {
        // Arrange
        var engine = new RuleMatchEngine(_loggerMock.Object);
        var rule = new BanRule
        {
            Enabled = true,
            Name = "Threshold Rule",
            Matching = new List<MatchExpression>
            {
                new MatchExpression
                {
                    Type = "regex",
                    Pattern = @"(?<ip>\d+\.\d+\.\d+\.\d+) - Connection refused"
                }
            },
            Action = new BanAction
            {
                Type = "threshold",
                MaxMatches = 3,
                WindowSeconds = 60,
                Reason = "Too many connection attempts",
                BanDurationSeconds = 3600
            }
        };

        // Act - Process 2 times (below threshold)
        var result1 = engine.ProcessLogLine("192.168.1.100 - Connection refused", rule);
        var result2 = engine.ProcessLogLine("192.168.1.100 - Connection refused", rule);

        // Assert - No ban yet
        Assert.Empty(result1);
        Assert.Empty(result2);

        // Act - Process 3rd time (reaches threshold)
        var result3 = engine.ProcessLogLine("192.168.1.100 - Connection refused", rule);

        // Assert - Ban triggered
        Assert.Single(result3);
        Assert.Equal("192.168.1.100", result3[0].ip);
    }

    [Fact]
    public void ProcessLogLine_WithJsonValueCondition_MatchesOnly()
    {
        // Arrange
        var engine = new RuleMatchEngine(_loggerMock.Object);
        var rule = new BanRule
        {
            Enabled = true,
            Name = "Status Code Rule",
            Matching = new List<MatchExpression>
            {
                new MatchExpression
                {
                    Type = "json",
                    JsonPath = "status",
                    JsonValue = "401"
                }
            },
            Action = new BanAction
            {
                Type = "immediate",
                Reason = "Unauthorized access",
                BanDurationSeconds = 1800
            }
        };

        // Act - Match 401
        var result1 = engine.ProcessLogLine(@"{""ip"":""192.168.1.50"",""status"":""401""}", rule);

        // Assert
        Assert.Single(result1);
        Assert.Equal("192.168.1.50", result1[0].ip);

        // Act - Different status
        var result2 = engine.ProcessLogLine(@"{""ip"":""192.168.1.51"",""status"":""200""}", rule);

        // Assert
        Assert.Empty(result2);
    }

    [Fact]
    public void ProcessLogLine_WithMultipleMatches_ReturnsAll()
    {
        // Arrange
        var engine = new RuleMatchEngine(_loggerMock.Object);
        var rule = new BanRule
        {
            Enabled = true,
            Name = "Multi IP Rule",
            Matching = new List<MatchExpression>
            {
                new MatchExpression
                {
                    Type = "regex",
                    Pattern = @"Failed: (?<ip>\d+\.\d+\.\d+\.\d+)"
                },
                new MatchExpression
                {
                    Type = "regex",
                    Pattern = @"Source: (?<ip>\d+\.\d+\.\d+\.\d+)"
                }
            },
            Action = new BanAction
            {
                Type = "immediate",
                Reason = "Attack detected",
                BanDurationSeconds = 3600
            }
        };

        // Act
        var result = engine.ProcessLogLine("Failed: 192.168.1.1 Source: 10.0.0.1", rule);

        // Assert
        Assert.Equal(2, result.Count);
        Assert.Contains(result, r => r.ip == "192.168.1.1");
        Assert.Contains(result, r => r.ip == "10.0.0.1");
    }

    [Fact]
    public void ProcessLogLine_WithInvalidRegex_HandlesGracefully()
    {
        // Arrange
        var engine = new RuleMatchEngine(_loggerMock.Object);
        var rule = new BanRule
        {
            Enabled = true,
            Name = "Invalid Regex",
            Matching = new List<MatchExpression>
            {
                new MatchExpression
                {
                    Type = "regex",
                    Pattern = @"(?<invalid>" // Invalid regex
                }
            },
            Action = new BanAction
            {
                Type = "immediate",
                Reason = "Test",
                BanDurationSeconds = 3600
            }
        };

        // Act & Assert - Should not throw
        var result = engine.ProcessLogLine("Some log line", rule);
        Assert.Empty(result);
    }

    [Fact]
    public void ProcessLogLine_WithInvalidJson_HandlesGracefully()
    {
        // Arrange
        var engine = new RuleMatchEngine(_loggerMock.Object);
        var rule = new BanRule
        {
            Enabled = true,
            Name = "JSON Rule",
            Matching = new List<MatchExpression>
            {
                new MatchExpression
                {
                    Type = "json",
                    JsonPath = "ip"
                }
            },
            Action = new BanAction
            {
                Type = "immediate",
                Reason = "Test",
                BanDurationSeconds = 3600
            }
        };

        // Act & Assert - Should not throw
        var result = engine.ProcessLogLine("Not valid JSON {broken}", rule);
        Assert.Empty(result);
    }

    [Fact]
    public void ProcessLogLine_NestedJsonPath_ExtractsCorrectly()
    {
        // Arrange
        var engine = new RuleMatchEngine(_loggerMock.Object);
        var rule = new BanRule
        {
            Enabled = true,
            Name = "Nested JSON",
            Matching = new List<MatchExpression>
            {
                new MatchExpression
                {
                    Type = "json",
                    JsonPath = "request.client_ip"
                }
            },
            Action = new BanAction
            {
                Type = "immediate",
                Reason = "Malicious request",
                BanDurationSeconds = 3600
            }
        };

        var logLine = @"{""request"":{""client_ip"":""203.0.113.42"",""method"":""POST""}}";

        // Act
        var result = engine.ProcessLogLine(logLine, rule);

        // Assert
        Assert.Single(result);
        Assert.Equal("203.0.113.42", result[0].ip);
    }
}
