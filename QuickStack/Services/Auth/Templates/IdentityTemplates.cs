using QuickStack.Models;

namespace QuickStack.Services.Auth.Templates;

public static class IdentityTemplates
{
    private static string P(ProjectOptions o) => o.ProjectName;

    public static string AppUser(ProjectOptions o)
    {
        var p = P(o);
        return $$"""
using Microsoft.AspNetCore.Identity;

namespace {{p}}.Infrastructure.Persistence;

public class AppUser : IdentityUser
{
    public string? FullName { get; set; }
}
""";
    }

    public static string IdentityDbContext(ProjectOptions o)
    {
        var p = P(o);
        var refreshTokenConfig = o.AuthFeatures.Contains(AuthFeatures.RefreshTokens)
            ? """
        
        builder.Entity<RefreshToken>(entity =>
        {
            entity.HasKey(e => e.Id);
            entity.HasIndex(e => e.TokenHash).IsUnique();
            entity.HasOne<AppUser>()
                .WithMany()
                .HasForeignKey(e => e.AppUserId)
                .OnDelete(DeleteBehavior.Cascade);
        });
"""
            : "";

        var domainUsing = "using " + p + ".Domain.Entities;\n";

        var permissionConfig = $$"""
        
        // ── Permission System Entity Configurations ────────────────

        builder.Entity<Permission>(entity =>
        {
            entity.HasKey(e => e.Id);
            entity.HasIndex(e => e.Code).IsUnique();
            entity.Property(e => e.Code).IsRequired().HasMaxLength(256);
            entity.Property(e => e.Module).IsRequired().HasMaxLength(128);
            entity.Property(e => e.Action).IsRequired().HasMaxLength(128);
            entity.Property(e => e.Risk).IsRequired().HasMaxLength(32).HasDefaultValue("Normal");
        });

        builder.Entity<RolePermission>(entity =>
        {
            entity.HasKey(e => e.Id);
            entity.HasIndex(e => new { e.RoleId, e.PermissionId }).IsUnique();
            entity.HasOne(e => e.Permission)
                .WithMany()
                .HasForeignKey(e => e.PermissionId)
                .OnDelete(DeleteBehavior.Cascade);
        });

        builder.Entity<UserPermission>(entity =>
        {
            entity.HasKey(e => e.Id);
            entity.HasIndex(e => new { e.UserId, e.PermissionId }).IsUnique();
            entity.HasOne(e => e.Permission)
                .WithMany()
                .HasForeignKey(e => e.PermissionId)
                .OnDelete(DeleteBehavior.Cascade);
        });

        builder.Entity<PermissionChangeLog>(entity =>
        {
            entity.HasKey(e => e.Id);
            entity.HasIndex(e => e.PermissionCode);
            entity.Property(e => e.PermissionCode).IsRequired().HasMaxLength(256);
        });

        // CRITICAL SECURITY FIX (audit tampering): PermissionAuditLog and
        // RoleAuditLog are configured as append-only tables. A migration
        // below will REVOKE UPDATE and DELETE privileges for the application's
        // runtime database user. See the generated migration for details.
        builder.Entity<PermissionAuditLog>(entity =>
        {
            entity.HasKey(e => e.Id);
            entity.HasIndex(e => e.Timestamp);
            entity.Property(e => e.TargetType).IsRequired().HasMaxLength(16);
            entity.Property(e => e.Action).IsRequired().HasMaxLength(32);
            entity.Property(e => e.PermissionCode).IsRequired().HasMaxLength(256);
        });

        builder.Entity<RoleAuditLog>(entity =>
        {
            entity.HasKey(e => e.Id);
            entity.HasIndex(e => e.Timestamp);
            entity.Property(e => e.Action).IsRequired().HasMaxLength(32);
        });
""";

        return $$"""
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
{{domainUsing}}
namespace {{p}}.Infrastructure.Persistence;

public class AppDbContext : IdentityDbContext<AppUser, ApplicationRole, string>
{
    public AppDbContext(DbContextOptions<AppDbContext> options) : base(options)
    {
    }

    // CRITICAL SECURITY FIX: Permission entities are the single source of truth
    // for authorization state. Never bypass these DbSets for permission checks.
    public DbSet<Permission> Permissions => Set<Permission>();
    public DbSet<RolePermission> RolePermissions => Set<RolePermission>();
    public DbSet<UserPermission> UserPermissions => Set<UserPermission>();
    public DbSet<PermissionChangeLog> PermissionChangeLogs => Set<PermissionChangeLog>();
    public DbSet<PermissionAuditLog> PermissionAuditLogs => Set<PermissionAuditLog>();
    public DbSet<RoleAuditLog> RoleAuditLogs => Set<RoleAuditLog>();

    protected override void OnModelCreating(ModelBuilder builder)
    {
        base.OnModelCreating(builder);
        {{refreshTokenConfig.TrimStart()}}
        {{permissionConfig.TrimStart()}}
    }
}
""";
    }

    public static string JwtTokenGenerator(ProjectOptions o)
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

public class JwtTokenGenerator : ITokenService
{
    private readonly JwtSettings _jwtSettings;

    public JwtTokenGenerator(IOptions<JwtSettings> jwtSettings)
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
