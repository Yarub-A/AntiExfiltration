using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using DataExfiltrationShield.ManagementAPI.Configuration;
using DataExfiltrationShield.ManagementAPI.Models;
using DataExfiltrationShield.ManagementAPI.Services;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

var builder = WebApplication.CreateBuilder(args);

var jwtSecret = builder.Configuration["JWT_SECRET"] ?? builder.Configuration["Jwt:Secret"] ?? string.Empty;
var jwtIssuer = builder.Configuration["Jwt:Issuer"] ?? "DataExfiltrationShield";
var jwtAudience = builder.Configuration["Jwt:Audience"] ?? "ManagementAPI";

builder.Services.Configure<JwtOptions>(options =>
{
    options.Secret = jwtSecret;
    options.Issuer = jwtIssuer;
    options.Audience = jwtAudience;
});

builder.Services.AddSingleton<IIncidentService, InMemoryIncidentService>();
builder.Services.AddSingleton<IAgentRegistry, InMemoryAgentRegistry>();

builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        if (string.IsNullOrWhiteSpace(jwtSecret))
        {
            options.TokenValidationParameters = new TokenValidationParameters
            {
                ValidateIssuer = false,
                ValidateAudience = false,
                ValidateIssuerSigningKey = false,
                ValidateLifetime = false
            };
            return;
        }

        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            ValidIssuer = jwtIssuer,
            ValidAudience = jwtAudience,
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtSecret))
        };
    });

builder.Services.AddAuthorization();

builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

var app = builder.Build();

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();
app.UseAuthentication();
app.UseAuthorization();

app.MapPost("/v1/events", ([FromBody] AgentEvent @event, IIncidentService incidentService, IAgentRegistry agentRegistry) =>
    {
        if (string.IsNullOrWhiteSpace(@event.AgentId))
        {
            return Results.BadRequest(new { error = "agentId is required" });
        }

        agentRegistry.MarkAgentSeen(@event.AgentId, @event.Hostname);
        incidentService.RecordEvent(@event);
        return Results.Accepted();
    })
    .RequireAuthorization();

app.MapGet("/v1/incidents/{id}", ([FromRoute] string id, IIncidentService incidentService) =>
    {
        var incident = incidentService.GetIncident(id);
        return incident is null ? Results.NotFound() : Results.Ok(incident);
    })
    .RequireAuthorization();

app.MapPost("/v1/actions/quarantine", ([FromBody] QuarantineRequest request, IIncidentService incidentService) =>
    {
        if (request.ProcessId <= 0)
        {
            return Results.BadRequest(new { error = "processId must be positive" });
        }

        var action = incidentService.RecordAction(request);
        return Results.Ok(action);
    })
    .RequireAuthorization();

app.MapGet("/v1/agents", (IAgentRegistry agentRegistry) => Results.Ok(agentRegistry.ListAgents()))
    .RequireAuthorization();

app.MapPost("/v1/auth/token", ([FromBody] TokenRequest request, IOptions<JwtOptions> options, IConfiguration configuration) =>
    {
        var jwtOptions = options.Value;
        if (string.IsNullOrWhiteSpace(jwtOptions.Secret))
        {
            return Results.Problem("JWT secret is not configured", statusCode: StatusCodes.Status500InternalServerError);
        }

        if (!string.Equals(request.ApiKey, configuration["MANAGEMENT_API_KEY"], StringComparison.Ordinal))
        {
            return Results.Unauthorized();
        }

        var handler = new JwtSecurityTokenHandler();
        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtOptions.Secret));
        var descriptor = new SecurityTokenDescriptor
        {
            Issuer = jwtOptions.Issuer,
            Audience = jwtOptions.Audience,
            Expires = DateTime.UtcNow.AddMinutes(30),
            Subject = new ClaimsIdentity(new[]
            {
                new Claim(ClaimTypes.NameIdentifier, request.ClientId),
                new Claim(ClaimTypes.Role, "management-client")
            }),
            SigningCredentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256)
        };

        var token = handler.CreateToken(descriptor);
        return Results.Ok(new TokenResponse(handler.WriteToken(token), descriptor.Expires!.Value));
    })
    .AllowAnonymous();

app.Run();

namespace DataExfiltrationShield.ManagementAPI.Configuration
{
    public class JwtOptions
    {
        public string Secret { get; set; } = string.Empty;
        public string Issuer { get; set; } = string.Empty;
        public string Audience { get; set; } = string.Empty;
    }
}
