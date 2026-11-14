using System.Text.Json.Serialization;

namespace FrpBan.Models;

[JsonSourceGenerationOptions(WriteIndented = true)]
[JsonSerializable(typeof(PluginRequest))]
[JsonSerializable(typeof(PluginResponse))]
[JsonSerializable(typeof(LoginContent))]
[JsonSerializable(typeof(NewUserConnContent))]
[JsonSerializable(typeof(List<BanEntry>))]
[JsonSerializable(typeof(BanEntry[]))]
internal partial class ServerJsonContext : JsonSerializerContext
{
}