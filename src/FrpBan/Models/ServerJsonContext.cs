using System.Text.Json.Serialization;

namespace FrpBan.Models;

/// <summary>frps plugin callback payloads.</summary>
[JsonSerializable(typeof(PluginRequest))]
[JsonSerializable(typeof(PluginResponse))]
[JsonSerializable(typeof(LoginContent))]
[JsonSerializable(typeof(NewUserConnContent))]
internal partial class ServerJsonContext : JsonSerializerContext
{
}

/// <summary>The persisted ban file format, indented so operators can inspect it.</summary>
[JsonSourceGenerationOptions(WriteIndented = true)]
[JsonSerializable(typeof(List<BanEntry>))]
[JsonSerializable(typeof(BanEntry[]))]
internal partial class BanStoreJsonContext : JsonSerializerContext
{
}
