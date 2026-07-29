using QuickStack.Models;

namespace QuickStack.Services.Auth.Templates;

public static class ServiceCollectionTemplates
{
    private static string P(ProjectOptions o) => o.ProjectName;

    private static string DbProviderOptions(ProjectOptions o)
    {
        return o.Database switch
        {
            DatabaseType.PostgreSql => """
            options.UseNpgsql(
                configuration.GetConnectionString("DefaultConnection"))
""",
            DatabaseType.Sqlite => """
            options.UseSqlite(
                configuration.GetConnectionString("DefaultConnection"))
""",
            DatabaseType.MySQL => """
            options.UseMySql(
                configuration.GetConnectionString("DefaultConnection"),
                ServerVersion.AutoDetect(configuration.GetConnectionString("DefaultConnection")))
""",
            DatabaseType.None => "",
            _ => """
            options.UseSqlServer(
                configuration.GetConnectionString("DefaultConnection"),
                sql => sql.EnableRetryOnFailure())
"""
        };
    }

    private static bool HasRefreshToken(ProjectOptions o) =>
        o.AuthFeatures.Contains(AuthFeatures.RefreshTokens);

    public static string IdentityServiceCollectionExtensions(ProjectOptions o)
    {
        var p = P(o);
        var dbOptions = DbProviderOptions(o);
        var hasRefresh = HasRefreshToken(o);

        return $$"""
using System.Text;
using {{p}}.Application.Interfaces;
using {{p}}.Infrastructure.Persistence;
using {{p}}.Infrastructure.Services;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;

namespace {{p}}.Infrastructure.DependencyInjection;

public static class IdentityServiceExtensions
{
    public static IServiceCollection AddIdentityServices(
        this IServiceCollection services,
        IConfiguration configuration)
    {
        services.AddDbContext<AppDbContext>(options =>
        {
{{dbOptions.TrimEnd()}};
            // CRITICAL SECURITY FIX (audit tampering): Registers the
            // AuditSaveChangesInterceptor which rejects UPDATE/DELETE on
            // PermissionAuditLog and RoleAuditLog at the application level.
            options.AddInterceptors(new AuditSaveChangesInterceptor());
        });

        services.AddIdentity<AppUser, ApplicationRole>(options =>
        {
            options.Password.RequireDigit = true;
            options.Password.RequiredLength = 8;
            options.Password.RequireNonAlphanumeric = false;
            options.SignIn.RequireConfirmedEmail = {{(o.AuthFeatures.Contains(AuthFeatures.AccountVerification) ? "true" : "false")}};
        })
        .AddEntityFrameworkStores<AppDbContext>()
        .AddDefaultTokenProviders();

        var jwtSettings = configuration.GetSection(JwtSettings.SectionName);
        services.Configure<JwtSettings>(jwtSettings);

        services.AddAuthentication(options =>
        {
            options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
            options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
        })
        .AddJwtBearer(options =>
        {
            options.TokenValidationParameters = new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidateAudience = true,
                ValidateLifetime = true,
                ValidateIssuerSigningKey = true,
                ValidIssuer = jwtSettings["Issuer"],
                ValidAudience = jwtSettings["Audience"],
                IssuerSigningKey = new SymmetricSecurityKey(
                    Encoding.UTF8.GetBytes(jwtSettings["SecretKey"]!))
            };
        });

        services.AddAuthorization();

        // Permission and role management services
        services.AddPermissionServices(includeRoleManagement: true);

        // Token services
        services.AddScoped<ITokenService, JwtTokenGenerator>();
{{(hasRefresh ? "        services.Configure<RefreshTokenSettings>(configuration.GetSection(RefreshTokenSettings.SectionName));" : "")}}
{{(hasRefresh ? "        services.AddScoped<IRefreshTokenService, RefreshTokenService>();" : "")}}

        // Security headers and cookie policy
        services.AddAntiforgery();
        services.ConfigureApplicationCookie(options =>
        {
            options.Cookie.HttpOnly = true;
            options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
            options.Cookie.SameSite = SameSiteMode.Strict;
        });

        return services;
    }
}
""";
    }

    public static string CustomJwtServiceCollectionExtensions(ProjectOptions o)
    {
        var p = P(o);
        var dbOptions = DbProviderOptions(o);
        var hasRefresh = HasRefreshToken(o);

        return $$"""
using System.Text;
using {{p}}.Application.Interfaces;
using {{p}}.Infrastructure.Persistence;
using {{p}}.Infrastructure.Services;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Http;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;

namespace {{p}}.Infrastructure.DependencyInjection;

public static class CustomJwtServiceExtensions
{
    public static IServiceCollection AddCustomJwtServices(
        this IServiceCollection services,
        IConfiguration configuration)
    {
        services.AddDbContext<AppDbContext>(options =>
        {
{{dbOptions.TrimEnd()}};
            // CRITICAL SECURITY FIX (audit tampering): Registers the
            // AuditSaveChangesInterceptor which rejects UPDATE/DELETE on
            // PermissionAuditLog and RoleAuditLog at the application level.
            options.AddInterceptors(new AuditSaveChangesInterceptor());
        });

        var jwtSettings = configuration.GetSection(JwtSettings.SectionName);
        services.Configure<JwtSettings>(jwtSettings);

        services.AddAuthentication(options =>
        {
            options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
            options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
        })
        .AddJwtBearer(options =>
        {
            options.TokenValidationParameters = new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidateAudience = true,
                ValidateLifetime = true,
                ValidateIssuerSigningKey = true,
                ValidIssuer = jwtSettings["Issuer"],
                ValidAudience = jwtSettings["Audience"],
                IssuerSigningKey = new SymmetricSecurityKey(
                    Encoding.UTF8.GetBytes(jwtSettings["SecretKey"]!))
            };
        });

        services.AddAuthorization();

        // CRITICAL SECURITY FIX: Permission and role management services.
        // Note: RoleManagementService depends on ASP.NET Core Identity and is
        // only available in IdentityWithJwt auth mode. For CustomJwt, only
        // core permission services (checking, caching, discovery, sync) are registered.
        services.AddPermissionServices(includeRoleManagement: false);

        // Token services
        services.AddScoped<ITokenService, TokenService>();
{{(hasRefresh ? "        services.Configure<RefreshTokenSettings>(configuration.GetSection(RefreshTokenSettings.SectionName));" : "")}}
{{(hasRefresh ? "        services.AddScoped<IRefreshTokenService, RefreshTokenService>();" : "")}}

        // Needed for accessing HttpContext in controllers (IP, User-Agent)
        services.AddHttpContextAccessor();

        // Security headers and cookie policy
        services.AddAntiforgery();
        services.ConfigureApplicationCookie(options =>
        {
            options.Cookie.HttpOnly = true;
            options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
            options.Cookie.SameSite = SameSiteMode.Strict;
        });

        return services;
    }
}
""";
    }

    public static string CustomJwtDbContext(ProjectOptions o)
    {
        var p = P(o);
        var refreshTokenConfig = o.AuthFeatures.Contains(AuthFeatures.RefreshTokens)
            ? """
        
        modelBuilder.Entity<RefreshToken>(entity =>
        {
            entity.HasKey(e => e.Id);
            entity.HasIndex(e => e.TokenHash).IsUnique();
            entity.HasOne<User>()
                .WithMany()
                .HasForeignKey(e => e.AppUserId)
                .OnDelete(DeleteBehavior.Cascade);
        });
"""
            : "";

        var permissionConfig = $$"""
        
        // ── Permission System Entity Configurations ────────────────

        modelBuilder.Entity<Permission>(entity =>
        {
            entity.HasKey(e => e.Id);
            entity.HasIndex(e => e.Code).IsUnique();
            entity.Property(e => e.Code).IsRequired().HasMaxLength(256);
            entity.Property(e => e.Module).IsRequired().HasMaxLength(128);
            entity.Property(e => e.Action).IsRequired().HasMaxLength(128);
            entity.Property(e => e.Risk).IsRequired().HasMaxLength(32).HasDefaultValue("Normal");
        });

        modelBuilder.Entity<RolePermission>(entity =>
        {
            entity.HasKey(e => e.Id);
            entity.HasIndex(e => new { e.RoleId, e.PermissionId }).IsUnique();
            entity.HasOne(e => e.Permission)
                .WithMany()
                .HasForeignKey(e => e.PermissionId)
                .OnDelete(DeleteBehavior.Cascade);
        });

        modelBuilder.Entity<UserPermission>(entity =>
        {
            entity.HasKey(e => e.Id);
            entity.HasIndex(e => new { e.UserId, e.PermissionId }).IsUnique();
            entity.HasOne(e => e.Permission)
                .WithMany()
                .HasForeignKey(e => e.PermissionId)
                .OnDelete(DeleteBehavior.Cascade);
        });

        modelBuilder.Entity<PermissionChangeLog>(entity =>
        {
            entity.HasKey(e => e.Id);
            entity.HasIndex(e => e.PermissionCode);
            entity.Property(e => e.PermissionCode).IsRequired().HasMaxLength(256);
        });

        // CRITICAL SECURITY FIX (audit tampering): These tables must be
        // append-only at the database level. Apply the following SQL after
        // running 'dotnet ef migrations add':
        //
        //   REVOKE UPDATE, DELETE ON PermissionAuditLog TO <app_user>;
        //   REVOKE UPDATE, DELETE ON RoleAuditLog TO <app_user>;
        //
        // Any attempt to modify/delete audit rows via EF will fail — this is
        // INTENTIONAL and must never be "fixed" by loosening the grant.
        modelBuilder.Entity<PermissionAuditLog>(entity =>
        {
            entity.HasKey(e => e.Id);
            entity.HasIndex(e => e.Timestamp);
            entity.Property(e => e.TargetType).IsRequired().HasMaxLength(16);
            entity.Property(e => e.Action).IsRequired().HasMaxLength(32);
            entity.Property(e => e.PermissionCode).IsRequired().HasMaxLength(256);
        });

        modelBuilder.Entity<RoleAuditLog>(entity =>
        {
            entity.HasKey(e => e.Id);
            entity.HasIndex(e => e.Timestamp);
            entity.Property(e => e.Action).IsRequired().HasMaxLength(32);
        });
""";

        return $$"""
using {{p}}.Domain.Entities;
using Microsoft.EntityFrameworkCore;

namespace {{p}}.Infrastructure.Persistence;

public class AppDbContext : DbContext
{
    public AppDbContext(DbContextOptions<AppDbContext> options) : base(options)
    {
    }

    public DbSet<User> Users => Set<User>();

    // CRITICAL SECURITY FIX: Permission entities are the single source of truth
    // for authorization state. Never bypass these DbSets for permission checks.
    public DbSet<Permission> Permissions => Set<Permission>();
    public DbSet<RolePermission> RolePermissions => Set<RolePermission>();
    public DbSet<UserPermission> UserPermissions => Set<UserPermission>();
    public DbSet<PermissionChangeLog> PermissionChangeLogs => Set<PermissionChangeLog>();
    public DbSet<PermissionAuditLog> PermissionAuditLogs => Set<PermissionAuditLog>();
    public DbSet<RoleAuditLog> RoleAuditLogs => Set<RoleAuditLog>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<User>(entity =>
        {
            entity.HasKey(e => e.Id);
            entity.HasIndex(e => e.Email).IsUnique();
            entity.Property(e => e.PasswordHash).IsRequired();
        });
        {{refreshTokenConfig.TrimStart()}}
        {{permissionConfig.TrimStart()}}

        base.OnModelCreating(modelBuilder);
    }
}
""";
    }
}
