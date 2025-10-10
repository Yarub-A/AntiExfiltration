using System.Text.Json.Serialization;

namespace DataExfiltrationShield.ManagementAPI.Models;

public record TokenRequest
{
    [JsonPropertyName("clientId")]
    public string ClientId { get; init; } = string.Empty;

    [JsonPropertyName("apiKey")]
    public string ApiKey { get; init; } = string.Empty;
}

public record TokenResponse(string Token, DateTimeOffset ExpiresAt);
