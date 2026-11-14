using System.Text.Json.Serialization;

namespace FrpBan.Protocol;

[JsonSourceGenerationOptions(RespectNullableAnnotations = true)]
[JsonSerializable(typeof(HelloMessage))]
[JsonSerializable(typeof(BanRequestMessage))]
[JsonSerializable(typeof(BanResponseMessage))]
[JsonSerializable(typeof(ErrorMessage))]
internal partial class ProtocolJsonContext : JsonSerializerContext
{
}