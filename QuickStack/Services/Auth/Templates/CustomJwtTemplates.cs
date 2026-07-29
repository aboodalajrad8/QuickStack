using QuickStack.Models;

namespace QuickStack.Services.Auth.Templates;

public static class CustomJwtTemplates
{
    private static string P(ProjectOptions o) => o.ProjectName;

    public static string UserEntity(ProjectOptions o)
    {
        var p = P(o);
        return $$"""
namespace {{p}}.Domain.Entities;

public class User
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public string Email { get; set; } = string.Empty;
    public string UserName { get; set; } = string.Empty;
    public string PasswordHash { get; set; } = string.Empty;
    public string? FullName { get; set; }
    public string? PhoneNumber { get; set; }
    public bool IsActive { get; set; } = true;

    // Email confirmation
    public bool EmailConfirmed { get; set; }
    public string? EmailConfirmationToken { get; set; }

    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
}
""";
    }

    public static string JwtSettings(ProjectOptions o)
    {
        var p = P(o);
        return $$"""
namespace {{p}}.Infrastructure.Services;

public class JwtSettings
{
    public const string SectionName = "JwtSettings";

    public string SecretKey { get; set; } = string.Empty;
    public string Issuer { get; set; } = string.Empty;
    public string Audience { get; set; } = string.Empty;

    /// <summary>Access token lifetime in minutes. Recommended: 15–60.</summary>
    public int ExpiryInMinutes { get; set; } = 15;
}

/// <summary>
/// Refresh token configuration stored in appsettings.json under "RefreshTokenSettings".
/// </summary>
public class RefreshTokenSettings
{
    public const string SectionName = "RefreshTokenSettings";

    /// <summary>Refresh token lifetime in days. Recommended: 7–30.</summary>
    public int RefreshTokenExpirationDays { get; set; } = 7;
}
""";
    }

    public static string ITokenService(ProjectOptions o)
    {
        var p = P(o);
        return $$"""
using System.Security.Claims;

namespace {{p}}.Application.Interfaces;

/// <summary>
/// Generates short-lived JWT access tokens.
/// For refresh token operations, see <see cref="IRefreshTokenService"/>.
/// </summary>
public interface ITokenService
{
    string GenerateToken(IEnumerable<Claim> claims, int? expiryInMinutes = null);
}
""";
    }

    public static string TokenService(ProjectOptions o)
    {
        var p = P(o);
        return $$"""
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using {{p}}.Application.Interfaces;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace {{p}}.Infrastructure.Services;

public class TokenService : ITokenService
{
    private readonly JwtSettings _jwtSettings;

    public TokenService(IOptions<JwtSettings> jwtSettings)
    {
        _jwtSettings = jwtSettings.Value;
    }

    public string GenerateToken(IEnumerable<Claim> claims, int? expiryInMinutes = null)
    {
        var key = new SymmetricSecurityKey(
            Encoding.UTF8.GetBytes(_jwtSettings.SecretKey));
        var credentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

        var allClaims = new List<Claim>(claims)
        {
            new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
        };

        var token = new JwtSecurityToken(
            issuer: _jwtSettings.Issuer,
            audience: _jwtSettings.Audience,
            claims: allClaims,
            expires: DateTime.UtcNow.AddMinutes(expiryInMinutes ?? _jwtSettings.ExpiryInMinutes),
            signingCredentials: credentials);

        return new JwtSecurityTokenHandler().WriteToken(token);
    }
}
""";
    }
}
