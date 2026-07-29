using QuickStack.Models;

namespace QuickStack.Services.Auth.Templates;

public static class RefreshTokenTemplates
{
    private static string P(ProjectOptions o) => o.ProjectName;

    public static string RefreshTokenEntity(ProjectOptions o)
    {
        var p = P(o);
        var userIdType = o.AuthType == AuthType.CustomJwt ? "Guid" : "string";
        return $$"""
namespace {{p}}.Domain.Entities;

/// <summary>
/// Stores a hashed refresh token linked to a user.
/// The raw token is never persisted — only its SHA-256 hash is stored.
/// When a token is rotated, the old record is revoked and a new one is created
/// within the same family. Reuse of a revoked token is treated as a breach
/// signal and revokes the entire token family.
/// </summary>
public class RefreshToken
{
    public Guid Id { get; set; } = Guid.NewGuid();

    /// <summary>SHA-256 hash of the refresh token. Never store the raw token.</summary>
    public string TokenHash { get; set; } = string.Empty;

    /// <summary>Groups tokens into a family for rotation. All tokens in a family
    /// are revoked if a reused (breached) token is detected.</summary>
    public string? FamilyId { get; set; }

    public DateTime ExpiresAt { get; set; }
    public bool IsExpired => DateTime.UtcNow >= ExpiresAt;

    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public DateTime? RevokedAt { get; set; }
    public bool IsRevoked => RevokedAt is not null;
    public bool IsActive => !IsExpired && !IsRevoked;

    /// <summary>Points to the token that replaced this one during rotation.
    /// Enables audit of the rotation chain.</summary>
    public Guid? ReplacedByTokenId { get; set; }

    /// <summary>IP address of the client at the time of token creation.</summary>
    public string? IPAddress { get; set; }

    /// <summary>User-Agent header of the client for device fingerprinting.</summary>
    public string? UserAgent { get; set; }

    /// <summary>Foreign key to the owning user.</summary>
    public {{userIdType}} AppUserId { get; set; } = default!;
}
""";
    }
}
