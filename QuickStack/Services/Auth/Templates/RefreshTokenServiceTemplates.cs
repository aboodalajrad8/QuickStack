using QuickStack.Models;

namespace QuickStack.Services.Auth.Templates;

public static class RefreshTokenServiceTemplates
{
    private static string P(ProjectOptions o) => o.ProjectName;

    public static string IRefreshTokenService(ProjectOptions o)
    {
        var p = P(o);
        return $$"""
namespace {{p}}.Application.Interfaces;

/// <summary>
/// Abstraction for refresh token operations.
/// Implementations can swap the backing store (EF Core, Redis, etc.)
/// without changing controller logic.
/// </summary>
public interface IRefreshTokenService
{
    /// <summary>Creates a new refresh token, stores its hash, and returns the raw token.</summary>
    Task<string> CreateAsync(string userId, string? ipAddress, string? userAgent, CancellationToken ct = default);

    /// <summary>
    /// Validates a refresh token against the stored hash.
    /// On success: revokes the old token, issues a new one in the same family.
    /// On reuse of a revoked token: revokes the entire family (breach signal).
    /// Returns a result indicating success, new token details, or failure reason.
    /// </summary>
    Task<RefreshTokenValidationResult> ValidateAndRotateAsync(string refreshToken, string? ipAddress, string? userAgent, CancellationToken ct = default);

    /// <summary>Revokes a single refresh token by its raw value.</summary>
    Task RevokeAsync(string refreshToken, CancellationToken ct = default);

    /// <summary>Revokes all active refresh tokens for a given user (logout from all devices).</summary>
    Task RevokeAllForUserAsync(string userId, CancellationToken ct = default);
}

/// <summary>
/// Result of a refresh token validation and rotation attempt.
/// </summary>
public class RefreshTokenValidationResult
{
    public bool Success { get; set; }
    public string? UserId { get; set; }
    public string? NewRefreshToken { get; set; }
    public DateTime? NewRefreshTokenExpiresAt { get; set; }
    public string? ErrorMessage { get; set; }
    public bool IsBreachDetected { get; set; }
}
""";
    }

    public static string RefreshTokenService(ProjectOptions o)
    {
        var p = P(o);
        var userIdType = o.AuthType == AuthType.CustomJwt ? "Guid" : "string";
        var userIdField = o.AuthType == AuthType.CustomJwt ? "Guid.Parse(userId)" : "userId";

        return $$"""
using System.ComponentModel.DataAnnotations;
using System.Security.Cryptography;
using System.Text;
using {{p}}.Application.Interfaces;
using {{p}}.Domain.Entities;
using {{p}}.Infrastructure.Persistence;
using {{p}}.Infrastructure.Services;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace {{p}}.Infrastructure.Services;

/// <summary>
/// Implements refresh token operations with security best practices:
/// - Token hashing (SHA-256) — raw token never stored in DB
/// - Token families for rotation tracking
/// - Breach detection: reuse of a rotated token revokes the entire family
/// - Device metadata (IP, User-Agent) for auditability
/// </summary>
public class RefreshTokenService : IRefreshTokenService
{
    private readonly AppDbContext _context;
    private readonly RefreshTokenSettings _settings;

    public RefreshTokenService(AppDbContext context, IOptions<RefreshTokenSettings> settings)
    {
        _context = context;
        _settings = settings.Value;
    }

    public async Task<string> CreateAsync(string userId, string? ipAddress, string? userAgent, CancellationToken ct = default)
    {
        var rawToken = GenerateCryptographicToken();
        var tokenHash = ComputeHash(rawToken);

        var entity = new RefreshToken
        {
            TokenHash = tokenHash,
            FamilyId = Guid.NewGuid().ToString(),
            ExpiresAt = DateTime.UtcNow.AddDays(_settings.RefreshTokenExpirationDays),
            IPAddress = ipAddress,
            UserAgent = userAgent,
            AppUserId = {{userIdField}}
        };

        _context.Set<RefreshToken>().Add(entity);
        await _context.SaveChangesAsync(ct);

        return rawToken;
    }

    public async Task<RefreshTokenValidationResult> ValidateAndRotateAsync(
        string refreshToken, string? ipAddress, string? userAgent, CancellationToken ct = default)
    {
        var tokenHash = ComputeHash(refreshToken);
        var stored = await _context.Set<RefreshToken>()
            .FirstOrDefaultAsync(rt => rt.TokenHash == tokenHash, ct);

        if (stored is null)
        {
            return new RefreshTokenValidationResult
            {
                Success = false,
                ErrorMessage = "Invalid refresh token."
            };
        }

        if (stored.IsExpired)
        {
            return new RefreshTokenValidationResult
            {
                Success = false,
                ErrorMessage = "Refresh token has expired."
            };
        }

        // ── Breach detection ──────────────────────────────────────────
        // If the token has already been revoked, someone may have stolen it.
        // Revoke the entire token family to limit damage.
        if (stored.RevokedAt is not null)
        {
            await RevokeTokenFamilyAsync(stored.FamilyId, ct);

            return new RefreshTokenValidationResult
            {
                Success = false,
                ErrorMessage = "Refresh token has been revoked.",
                IsBreachDetected = true
            };
        }

        // ── Rotate: revoke old, issue new ─────────────────────────────
        var rawToken = GenerateCryptographicToken();
        var newHash = ComputeHash(rawToken);

        var newEntity = new RefreshToken
        {
            TokenHash = newHash,
            FamilyId = stored.FamilyId,
            ExpiresAt = DateTime.UtcNow.AddDays(_settings.RefreshTokenExpirationDays),
            IPAddress = ipAddress,
            UserAgent = userAgent,
            AppUserId = stored.AppUserId
        };

        stored.RevokedAt = DateTime.UtcNow;
        stored.ReplacedByTokenId = newEntity.Id;

        _context.Set<RefreshToken>().Add(newEntity);
        await _context.SaveChangesAsync(ct);

        return new RefreshTokenValidationResult
        {
            Success = true,
            UserId = stored.AppUserId.ToString(),
            NewRefreshToken = rawToken,
            NewRefreshTokenExpiresAt = newEntity.ExpiresAt
        };
    }

    public async Task RevokeAsync(string refreshToken, CancellationToken ct = default)
    {
        var tokenHash = ComputeHash(refreshToken);
        var stored = await _context.Set<RefreshToken>()
            .FirstOrDefaultAsync(rt => rt.TokenHash == tokenHash, ct);

        if (stored is not null && stored.RevokedAt is null)
        {
            stored.RevokedAt = DateTime.UtcNow;
            await _context.SaveChangesAsync(ct);
        }
    }

    public async Task RevokeAllForUserAsync(string userId, CancellationToken ct = default)
    {
        var {{(o.AuthType == AuthType.CustomJwt ? "uid = Guid.Parse(userId)" : "uid = userId")}};
        var activeTokens = await _context.Set<RefreshToken>()
            .Where(rt => rt.AppUserId == uid && rt.RevokedAt == null)
            .ToListAsync(ct);

        var now = DateTime.UtcNow;
        foreach (var token in activeTokens)
        {
            token.RevokedAt = now;
        }

        await _context.SaveChangesAsync(ct);
    }

    private async Task RevokeTokenFamilyAsync(string? familyId, CancellationToken ct)
    {
        if (string.IsNullOrEmpty(familyId)) return;

        var familyTokens = await _context.Set<RefreshToken>()
            .Where(rt => rt.FamilyId == familyId && rt.RevokedAt == null)
            .ToListAsync(ct);

        var now = DateTime.UtcNow;
        foreach (var token in familyTokens)
        {
            token.RevokedAt = now;
        }

        await _context.SaveChangesAsync(ct);
    }

    private static string GenerateCryptographicToken()
    {
        return Convert.ToBase64String(RandomNumberGenerator.GetBytes(64));
    }

    private static string ComputeHash(string input)
    {
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(input));
        return Convert.ToHexString(bytes).ToLowerInvariant();
    }
}
""";
    }
}
