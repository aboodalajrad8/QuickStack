using QuickStack.Models;

namespace QuickStack.Services.Auth.Templates;

public static class PermissionTemplates
{
    private static string P(ProjectOptions o) => o.ProjectName;
    private static string UsingDomain(ProjectOptions o) => $"using {P(o)}.Domain;\n";
    private static string UsingDomainEntities(ProjectOptions o) => $"using {P(o)}.Domain.Entities;\n";
    private static string UsingDomainEnums(ProjectOptions o) => $"using {P(o)}.Domain.Enums;\n";

    // ═══════════════════════════════════════════════════════════════
    //  DOMAIN LAYER
    // ═══════════════════════════════════════════════════════════════

    public static string PermissionRiskEnum(ProjectOptions o)
    {
        var p = P(o);
        return $$"""
namespace {{p}}.Domain.Enums;

public enum PermissionRisk
{
    /// <summary>Low-risk permissions (e.g., read-only operations).</summary>
    Low = 0,

    /// <summary>Normal-risk permissions (e.g., standard create/update operations).</summary>
    Normal = 1,

    /// <summary>
    /// Critical-risk permissions (e.g., permissions.manage, roles.manage).
    /// These bypass cache and are always live-checked against the database.
    /// The last user/role holding a Critical permission cannot have it revoked.
    /// </summary>
    Critical = 2
}
""";
    }

    public static string InvalidPermissionCodeException(ProjectOptions o)
    {
        var p = P(o);
        return $$"""
namespace {{p}}.Domain.Exceptions;

public class InvalidPermissionCodeException : Exception
{
    public InvalidPermissionCodeException(string message) : base(message)
    {
    }

    public InvalidPermissionCodeException(string message, Exception inner) : base(message, inner)
    {
    }
}
""";
    }

    public static string ForbiddenException(ProjectOptions o)
    {
        var p = P(o);
        return $$"""
namespace {{p}}.Domain.Exceptions;

public class ForbiddenException : Exception
{
    public string? PermissionCode { get; }

    public ForbiddenException(string message) : base(message)
    {
    }

    public ForbiddenException(string message, string permissionCode) : base(message)
    {
        PermissionCode = permissionCode;
    }
}
""";
    }

    public static string NotFoundException(ProjectOptions o)
    {
        var p = P(o);
        return $$"""
namespace {{p}}.Domain.Exceptions;

public class NotFoundException : Exception
{
    public string EntityName { get; }
    public object EntityId { get; }

    public NotFoundException(string entityName, object entityId)
        : base($"Entity '{entityName}' with id '{entityId}' was not found.")
    {
        EntityName = entityName;
        EntityId = entityId;
    }
}
""";
    }

    public static string IOwnedEntityInterface(ProjectOptions o)
    {
        var p = P(o);
        return $$"""
namespace {{p}}.Domain.Entities;

/// <summary>
/// CRITICAL SECURITY: Interface for resource-level authorization.
/// Entities that implement this interface enable automatic ownership
/// checks in the DefaultOwnershipResourceAuthorizationService.
/// </summary>
public interface IOwnedEntity
{
    string OwnerId { get; }
}
""";
    }

    // ── Domain Entities ─────────────────────────────────────────

    public static string PermissionEntity(ProjectOptions o)
    {
        var p = P(o);
        return $$"""
namespace {{p}}.Domain.Entities;

public class Permission
{
    public string Id { get; set; } = Guid.NewGuid().ToString("N");
    public string Code { get; set; } = string.Empty;
    public string Module { get; set; } = string.Empty;
    public string Action { get; set; } = string.Empty;
    public string? DisplayName { get; set; }
    public string? Description { get; set; }
    public string Risk { get; set; } = "Normal";
    public bool ForceLiveCheck { get; set; }
    public bool IsOrphaned { get; set; }
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public DateTime UpdatedAt { get; set; } = DateTime.UtcNow;
}
""";
    }

    public static string RolePermissionEntity(ProjectOptions o)
    {
        var p = P(o);
        return $$"""
namespace {{p}}.Domain.Entities;

public class RolePermission
{
    public string Id { get; set; } = Guid.NewGuid().ToString("N");
    public string RoleId { get; set; } = string.Empty;
    public string PermissionId { get; set; } = string.Empty;
    public Permission Permission { get; set; } = null!;
}
""";
    }

    public static string UserPermissionEntity(ProjectOptions o)
    {
        var p = P(o);
        return $$"""
namespace {{p}}.Domain.Entities;

public class UserPermission
{
    public string Id { get; set; } = Guid.NewGuid().ToString("N");
    public string UserId { get; set; } = string.Empty;
    public string PermissionId { get; set; } = string.Empty;
    public Permission Permission { get; set; } = null!;

    /// <summary>If true, the permission is explicitly granted. If false, it is explicitly denied.</summary>
    public bool IsGranted { get; set; }
}
""";
    }

    public static string PermissionChangeLogEntity(ProjectOptions o)
    {
        var p = P(o);
        return $$"""
namespace {{p}}.Domain.Entities;

/// <summary>
/// CRITICAL SECURITY FIX (semantic drift): Records changes to existing
/// permission metadata. When a developer changes what an existing permission
/// code protects (e.g., broadening scope) without renaming it, this log entry
/// makes that expansion visible and reviewable.
/// </summary>
public class PermissionChangeLog
{
    public string Id { get; set; } = Guid.NewGuid().ToString("N");
    public string PermissionCode { get; set; } = string.Empty;
    public string? OldDisplayName { get; set; }
    public string? NewDisplayName { get; set; }
    public string? OldDescription { get; set; }
    public string? NewDescription { get; set; }
    public string? OldRisk { get; set; }
    public string? NewRisk { get; set; }
    public DateTime ChangedAt { get; set; } = DateTime.UtcNow;
    public string? SourceCommitSha { get; set; }
}
""";
    }

    public static string PermissionAuditLogEntity(ProjectOptions o)
    {
        var p = P(o);
        return $$"""
namespace {{p}}.Domain.Entities;

/// <summary>
/// CRITICAL SECURITY FIX (audit tampering): This table is append-only at the
/// database privilege level — UPDATE and DELETE are REVOKEd for the
/// application's runtime DB user. Any EF SaveChangesAsync call that tries to
/// modify or delete a row here will fail. This is INTENTIONAL and must never
/// be "fixed" by loosening the grant.
/// </summary>
public class PermissionAuditLog
{
    public string Id { get; set; } = Guid.NewGuid().ToString("N");
    public string ActorUserId { get; set; } = string.Empty;
    public string TargetType { get; set; } = string.Empty; // "Role" or "User"
    public string TargetId { get; set; } = string.Empty;
    public string PermissionCode { get; set; } = string.Empty;
    public string Action { get; set; } = string.Empty; // "Granted", "Revoked", "Denied", "OverrideRemoved"
    public DateTime Timestamp { get; set; } = DateTime.UtcNow;
    public string? ActorIpAddress { get; set; }
}
""";
    }

    public static string RoleAuditLogEntity(ProjectOptions o)
    {
        var p = P(o);
        return $$"""
namespace {{p}}.Domain.Entities;

/// <summary>
/// CRITICAL SECURITY FIX (audit tampering): Same append-only protection as
/// PermissionAuditLog. UPDATE and DELETE are REVOKEd at the DB level.
/// </summary>
public class RoleAuditLog
{
    public string Id { get; set; } = Guid.NewGuid().ToString("N");
    public string ActorUserId { get; set; } = string.Empty;
    public string Action { get; set; } = string.Empty; // "Created", "Deleted", "Renamed", "UserAssigned", "UserRemoved"
    public string TargetRoleId { get; set; } = string.Empty;
    public string? TargetUserId { get; set; }
    public string? Details { get; set; }
    public DateTime Timestamp { get; set; } = DateTime.UtcNow;
}
""";
    }

    public static string ApplicationRoleEntity(ProjectOptions o)
    {
        var p = P(o);
        return $$"""
using Microsoft.AspNetCore.Identity;

namespace {{p}}.Infrastructure.Persistence;

public class ApplicationRole : IdentityRole
{
    public string? Description { get; set; }

    /// <summary>
    /// System roles (e.g., "SuperAdmin") are seeded and cannot be deleted
    /// or renamed via the management API.
    /// </summary>
    public bool IsSystemRole { get; set; }
}
""";
    }

    // ═══════════════════════════════════════════════════════════════
    //  APPLICATION LAYER — DTOs
    // ═══════════════════════════════════════════════════════════════

    public static string PermissionDto(ProjectOptions o)
    {
        var p = P(o);
        return $$"""
namespace {{p}}.Application.DTOs.Permission;

public class PermissionDto
{
    public string Id { get; set; } = string.Empty;
    public string Code { get; set; } = string.Empty;
    public string Module { get; set; } = string.Empty;
    public string Action { get; set; } = string.Empty;
    public string? DisplayName { get; set; }
    public string? Description { get; set; }
    public string Risk { get; set; } = "Normal";
    public bool IsOrphaned { get; set; }
}

public class PermissionSyncResultDto
{
    public int Inserted { get; set; }
    public int Updated { get; set; }
    public int Orphaned { get; set; }
    public int Unchanged { get; set; }
    public List<PermissionChangeLogDto> ChangeLogs { get; set; } = new();
}

public class PermissionChangeLogDto
{
    public string PermissionCode { get; set; } = string.Empty;
    public string? OldDisplayName { get; set; }
    public string? NewDisplayName { get; set; }
    public string? OldDescription { get; set; }
    public string? NewDescription { get; set; }
    public string? OldRisk { get; set; }
    public string? NewRisk { get; set; }
    public DateTime ChangedAt { get; set; }
    public string? SourceCommitSha { get; set; }
}
""";
    }

    public static string RoleDto(ProjectOptions o)
    {
        var p = P(o);
        return $$"""
namespace {{p}}.Application.DTOs.Permission;

public class RoleDto
{
    public string Id { get; set; } = string.Empty;
    public string Name { get; set; } = string.Empty;
    public string? Description { get; set; }
    public bool IsSystemRole { get; set; }
    public int UserCount { get; set; }
    public List<string> Permissions { get; set; } = new();
}

public class UserPermissionDto
{
    public string UserId { get; set; } = string.Empty;
    public string PermissionCode { get; set; } = string.Empty;
    public bool IsGranted { get; set; }
    public string Source { get; set; } = "Role"; // "Role", "UserOverride"
}

public class GrantPermissionRequest
{
    public string PermissionCode { get; set; } = string.Empty;
}

public class SetUserPermissionRequest
{
    public string PermissionCode { get; set; } = string.Empty;
    public bool IsGranted { get; set; }
}

public class CreateRoleRequest
{
    public string Name { get; set; } = string.Empty;
    public string? Description { get; set; }
}

public class RenameRoleRequest
{
    public string NewName { get; set; } = string.Empty;
}

public class AssignUserRequest
{
    public string UserId { get; set; } = string.Empty;
}
""";
    }

    // ═══════════════════════════════════════════════════════════════
    //  APPLICATION LAYER — EXCEPTIONS & EXTENSIONS
    // ═══════════════════════════════════════════════════════════════

    public static string PermissionNotFoundException(ProjectOptions o)
    {
        var p = P(o);
        return $$"""
namespace {{p}}.Domain.Exceptions;

public class PermissionNotFoundException : Exception
{
    public string PermissionCode { get; }

    public PermissionNotFoundException(string permissionCode)
        : base($"Permission '{permissionCode}' was not found. Permissions must be discovered from code first (run 'quickstack permissions sync').")
    {
        PermissionCode = permissionCode;
    }
}
""";
    }

    public static string ClaimsPrincipalExtensions(ProjectOptions o)
    {
        var p = P(o);
        return $$"""
using System.Security.Claims;

namespace {{p}}.Application.Extensions;

public static class ClaimsPrincipalExtensions
{
    /// <summary>
    /// Retrieves the user ID from the NameIdentifier claim.
    /// Throws if the claim is missing — every authenticated request must have it.
    /// </summary>
    public static string GetUserId(this ClaimsPrincipal principal)
    {
        var userId = principal.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        if (string.IsNullOrEmpty(userId))
            throw new UnauthorizedAccessException("User identifier claim (NameIdentifier) is missing from the token.");
        return userId;
    }
}
""";
    }

    // ═══════════════════════════════════════════════════════════════
    //  APPLICATION LAYER — INTERFACES
    // ═══════════════════════════════════════════════════════════════

    public static string IPermissionServiceInterface(ProjectOptions o)
    {
        var p = P(o);
        return $$"""
namespace {{p}}.Application.Authorization;

/// <summary>
/// Single source of truth for runtime permission checks.
/// All authorization flows through this service — never through
/// User.HasClaim or JWT claims directly.
/// </summary>
public interface IPermissionService
{
    /// <summary>
    /// Checks whether a user holds a specific permission.
    /// Resolution order: user override → role permissions → deny.
    /// </summary>
    /// <param name="userId">The user's ID (from NameIdentifier claim).</param>
    /// <param name="permissionCode">Permission code in "module.action" format.</param>
    /// <param name="forceLiveCheck">
    /// If true, skip cache entirely and query the database directly.
    /// Required for all Critical-risk permissions.
    /// </param>
    Task<bool> UserHasPermissionAsync(string userId, string permissionCode, bool forceLiveCheck = false);
}
""";
    }

    public static string IPermissionCacheInterface(ProjectOptions o)
    {
        var p = P(o);
        return $$"""
namespace {{p}}.Application.Authorization;

public interface IPermissionCache
{
    Task<bool?> GetAsync(string userId, string permissionCode);
    Task SetAsync(string userId, string permissionCode, bool hasPermission);
    Task RemoveAsync(string userId);
    Task RemoveByRoleAsync(string roleId);
    Task ClearAsync();
}
""";
    }

    public static string IResourceAuthorizationServiceInterface(ProjectOptions o)
    {
        var p = P(o);
        return $$"""
namespace {{p}}.Application.Authorization;

/// <summary>
/// CRITICAL SECURITY FIX (IDOR prevention): Resource-level authorization.
/// [RequirePermission] only proves the user holds a class of permission —
/// it does NOT prove the user is allowed to act on a SPECIFIC resource
/// instance. This interface fills that gap.
/// </summary>
/// <typeparam name="TResource">The entity type to authorize against.</typeparam>
public interface IResourceAuthorizationService<TResource>
{
    /// <summary>
    /// Checks whether a user can perform the specified action on the given resource instance.
    /// </summary>
    Task<bool> CanAccessAsync(string userId, TResource resource, string action);
}
""";
    }

    public static string IPermissionManagementServiceInterface(ProjectOptions o)
    {
        var p = P(o);
        return $$"""
using {{p}}.Application.DTOs.Permission;

namespace {{p}}.Application.Authorization;

public interface IPermissionManagementService
{
    Task<List<PermissionDto>> GetAllPermissionsAsync();
    Task<PermissionDto?> GetPermissionByCodeAsync(string code);
    Task GrantPermissionToRoleAsync(string roleId, string permissionCode);
    Task RevokePermissionFromRoleAsync(string roleId, string permissionCode);
    Task<List<string>> GetRolePermissionsAsync(string roleId);
    Task SetUserPermissionOverrideAsync(string userId, string permissionCode, bool isGranted);
    Task RemoveUserPermissionOverrideAsync(string userId, string permissionCode);
    Task<List<PermissionDto>> GetEffectivePermissionsAsync(string userId);
    Task<PermissionSyncResultDto> SyncPermissionsAsync(
        List<(string Code, string Module, string Action, string? DisplayName, string? Description, string Risk, bool ForceLiveCheck)> discoveredPermissions,
        bool grantNewToSuperAdmin = false,
        string? sourceCommitSha = null);
    Task<PermissionSyncResultDto> DiffPermissionsAsync(
        List<(string Code, string Module, string Action, string? DisplayName, string? Description, string Risk, bool ForceLiveCheck)> discoveredPermissions);
    Task<List<PermissionChangeLogDto>> GetChangeLogAsync();
    Task PruneOrphanedPermissionsAsync();
}
""";
    }

    public static string IRoleManagementServiceInterface(ProjectOptions o)
    {
        var p = P(o);
        return $$"""
using {{p}}.Application.DTOs.Permission;

namespace {{p}}.Application.Authorization;

public interface IRoleManagementService
{
    Task<List<RoleDto>> GetAllRolesAsync();
    Task<RoleDto> CreateRoleAsync(string name, string? description, string actorUserId, string? actorIpAddress = null);
    Task RenameRoleAsync(string roleId, string newName, string actorUserId, string? actorIpAddress = null);
    Task DeleteRoleAsync(string roleId, string actorUserId, string? actorIpAddress = null);
    Task AssignUserToRoleAsync(string userId, string roleId, string actorUserId, string? actorIpAddress = null);
    Task RemoveUserFromRoleAsync(string userId, string roleId, string actorUserId, string? actorIpAddress = null);
    Task<List<UserDto>> GetUsersInRoleAsync(string roleId);
}

public class UserDto
{
    public string Id { get; set; } = string.Empty;
    public string UserName { get; set; } = string.Empty;
    public string Email { get; set; } = string.Empty;
}
""";
    }

    // ═══════════════════════════════════════════════════════════════
    //  INFRASTRUCTURE LAYER — PERMISSION CACHE
    // ═══════════════════════════════════════════════════════════════

    public static string PermissionCacheClass(ProjectOptions o)
    {
        var p = P(o);
        return $$"""
using System.Collections.Concurrent;
using Microsoft.Extensions.Logging;

namespace {{p}}.Infrastructure.Authorization;

public class PermissionCache : Application.Authorization.IPermissionCache
{
    private static readonly ConcurrentDictionary<string, ConcurrentDictionary<string, CacheEntry>> _cache = new();
    private static readonly ConcurrentDictionary<string, HashSet<string>> _roleUserIndex = new();
    private readonly ILogger<PermissionCache> _logger;
    private static readonly TimeSpan DefaultTtl = TimeSpan.FromMinutes(5);
    private readonly TimeSpan _ttl;

    public PermissionCache(ILogger<PermissionCache> logger) : this(logger, DefaultTtl)
    {
    }

    public PermissionCache(ILogger<PermissionCache> logger, TimeSpan ttl)
    {
        _logger = logger;
        _ttl = ttl;
    }

    public Task<bool?> GetAsync(string userId, string permissionCode)
    {
        if (_cache.TryGetValue(userId, out var userPermissions) &&
            userPermissions.TryGetValue(permissionCode, out var entry))
        {
            if (DateTime.UtcNow < entry.ExpiresAt)
            {
                return Task.FromResult<bool?>(entry.Value);
            }
            userPermissions.TryRemove(permissionCode, out _);
        }
        return Task.FromResult<bool?>(null);
    }

    public Task SetAsync(string userId, string permissionCode, bool hasPermission)
    {
        var userPermissions = _cache.GetOrAdd(userId, _ => new ConcurrentDictionary<string, CacheEntry>());
        userPermissions[permissionCode] = new CacheEntry(hasPermission, DateTime.UtcNow.Add(_ttl));
        return Task.CompletedTask;
    }

    public Task RemoveAsync(string userId)
    {
        _cache.TryRemove(userId, out _);
        return Task.CompletedTask;
    }

    public Task RemoveByRoleAsync(string roleId)
    {
        if (_roleUserIndex.TryGetValue(roleId, out var userIds))
        {
            foreach (var userId in userIds)
            {
                _cache.TryRemove(userId, out _);
            }
        }
        return Task.CompletedTask;
    }

    public void TrackUserRole(string userId, string roleId)
    {
        var users = _roleUserIndex.GetOrAdd(roleId, _ => new HashSet<string>());
        lock (users)
        {
            users.Add(userId);
        }
    }

    public Task ClearAsync()
    {
        _cache.Clear();
        _roleUserIndex.Clear();
        return Task.CompletedTask;
    }

    private record CacheEntry(bool Value, DateTime ExpiresAt);
}
""";
    }

    // ═══════════════════════════════════════════════════════════════
    //  INFRASTRUCTURE LAYER — PERMISSION SERVICE
    // ═══════════════════════════════════════════════════════════════

    public static string PermissionServiceClass(ProjectOptions o)
    {
        var p = P(o);
        var rawRoleLookupIdentity = """
        var userRoles = await _db.UserRoles
            .Where(ur => ur.UserId == userId)
            .Select(ur => ur.RoleId)
            .ToListAsync();
""";
        var rawRoleLookupCustomJwt = """
        // CustomJwt: no Identity UserRoles — skip role-based check
        var userRoles = new List<string>();
""";
        return $$"""
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using {{p}}.Application.Authorization;
using {{p}}.Domain.Entities;
using {{p}}.Infrastructure.Persistence;

namespace {{p}}.Infrastructure.Authorization;

public class PermissionService : IPermissionService
{
    private readonly AppDbContext _db;
    private readonly IPermissionCache _cache;
    private readonly ILogger<PermissionService> _logger;
    private readonly HashSet<string> _alwaysLiveCheckCodes;

    public PermissionService(
        AppDbContext db,
        IPermissionCache cache,
        IConfiguration configuration,
        ILogger<PermissionService> logger)
    {
        _db = db;
        _cache = cache;
        _logger = logger;

        // Read the list of permission codes that must always bypass cache
        var liveCheckConfig = configuration.GetSection("Permissions:AlwaysLiveCheck").Get<string[]>();
        _alwaysLiveCheckCodes = new HashSet<string>(liveCheckConfig ?? Array.Empty<string>(), StringComparer.OrdinalIgnoreCase);
    }

    public async Task<bool> UserHasPermissionAsync(string userId, string permissionCode, bool forceLiveCheck = false)
    {
        // CRITICAL SECURITY FIX: If forceLiveCheck is true (set via
        // RequirePermissionAttribute.ForceLiveCheck), or if the permission code
        // is in the always-live-check list, skip cache entirely and query the
        // database directly. This prevents stale-cache exploitation for critical
        // permissions.
        var liveCheck = forceLiveCheck || _alwaysLiveCheckCodes.Contains(permissionCode);

        if (!liveCheck)
        {
            var cached = await _cache.GetAsync(userId, permissionCode);
            if (cached.HasValue)
            {
                return cached.Value;
            }
        }

        // Resolution order:
        // 1. Check UserPermissions for explicit per-user override
        var userPermission = await _db.Set<UserPermission>()
            .Include(up => up.Permission)
            .FirstOrDefaultAsync(up => up.UserId == userId && up.Permission.Code == permissionCode);

        if (userPermission != null)
        {
            // CRITICAL SECURITY FIX: User override is FINAL regardless of role.
            // If explicitly denied, the user cannot gain this permission through any role.
            if (!liveCheck)
            {
                await _cache.SetAsync(userId, permissionCode, userPermission.IsGranted);
            }
            return userPermission.IsGranted;
        }

        // 2. Check RolePermissions via the user's roles
{{(o.AuthType == AuthType.IdentityWithJwt ? rawRoleLookupIdentity : rawRoleLookupCustomJwt)}}
        if (userRoles.Count > 0)
        {
            var hasRolePermission = await _db.Set<RolePermission>()
                .Include(rp => rp.Permission)
                .AnyAsync(rp => userRoles.Contains(rp.RoleId) && rp.Permission.Code == permissionCode);

            if (hasRolePermission)
            {
                if (!liveCheck)
                {
                    await _cache.SetAsync(userId, permissionCode, true);
                }
                return true;
            }
        }

        // 3. Otherwise deny
        if (!liveCheck)
        {
            await _cache.SetAsync(userId, permissionCode, false);
        }
        return false;
    }
}
""";
    }

    // ═══════════════════════════════════════════════════════════════
    //  INFRASTRUCTURE LAYER — RESOURCE AUTHORIZATION
    // ═══════════════════════════════════════════════════════════════

    public static string DefaultOwnershipResourceAuthorizationServiceClass(ProjectOptions o)
    {
        var p = P(o);
        return $$"""
using Microsoft.Extensions.Logging;
using {{p}}.Application.Authorization;
using {{p}}.Domain.Entities;

namespace {{p}}.Infrastructure.Authorization;

/// <summary>
/// CRITICAL SECURITY FIX (IDOR prevention): Default resource-level authorization
/// that checks ownership via IOwnedEntity and falls back to the broad ".any"
/// permission variant if the entity doesn't implement IOwnedEntity.
///
/// IMPORTANT: This is a safe-but-explicit default. Consuming developers MUST
/// review and customize this per entity. For entities without ownership, the
/// ".any" permission variant (e.g., "invoices.update.any") must be explicitly
/// granted — no silent elevation.
/// </summary>
public class DefaultOwnershipResourceAuthorizationService<TResource> : IResourceAuthorizationService<TResource>
{
    private readonly IPermissionService _permissionService;
    private readonly ILogger<DefaultOwnershipResourceAuthorizationService<TResource>> _logger;

    public DefaultOwnershipResourceAuthorizationService(
        IPermissionService permissionService,
        ILogger<DefaultOwnershipResourceAuthorizationService<TResource>> logger)
    {
        _permissionService = permissionService;
        _logger = logger;
    }

    public async Task<bool> CanAccessAsync(string userId, TResource resource, string action)
    {
        // Derive the module name from the type name (pluralized convention)
        var typeName = typeof(TResource).Name;
        var module = typeName.EndsWith("y")
            ? typeName[..^1] + "ies"
            : typeName.EndsWith("s") ? typeName : typeName + "s";
        module = module.ToLowerInvariant();

        if (resource is IOwnedEntity owned)
        {
            // CRITICAL SECURITY FIX: If the entity implements IOwnedEntity,
            // the user must either own the resource OR hold the ".any" permission.
            if (string.Equals(owned.OwnerId, userId, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }

            // Check the ".any" variant for cross-tenant/admin access
            var anyPermission = $"{module}.{action}.any";
            if (await _permissionService.UserHasPermissionAsync(userId, anyPermission))
            {
                return true;
            }

            _logger.LogWarning(
                "Resource authorization denied: UserId={UserId} Resource={ResourceType} Action={Action}",
                userId, typeof(TResource).Name, action);
            return false;
        }

        // No ownership interface — fall back to ".any" permission check.
        // This requires explicit configuration; it is not a silent grant.
        var broadPermission = $"{module}.{action}.any";
        var hasBroad = await _permissionService.UserHasPermissionAsync(userId, broadPermission);
        if (!hasBroad)
        {
            _logger.LogWarning(
                "Resource authorization denied (no ownership): UserId={UserId} Resource={ResourceType} Action={Action}",
                userId, typeof(TResource).Name, action);
        }
        return hasBroad;
    }
}
""";
    }

    // ═══════════════════════════════════════════════════════════════
    //  INFRASTRUCTURE LAYER — PERMISSION DISCOVERY
    // ═══════════════════════════════════════════════════════════════

    public static string PermissionDiscoveryServiceClass(ProjectOptions o)
    {
        var p = P(o);
        return $$"""
using System.Reflection;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;

namespace {{p}}.Infrastructure.Authorization;

public class PermissionDiscoveryService
{
    private static readonly string[] RequireAttrNames = { "RequirePermissionAttribute", "RequirePermission" };
    private static readonly string[] RequireAnyAttrNames = { "RequireAnyPermissionAttribute", "RequireAnyPermission" };

    private readonly IConfiguration _configuration;
    private readonly ILogger<PermissionDiscoveryService> _logger;

    public PermissionDiscoveryService(
        IConfiguration configuration,
        ILogger<PermissionDiscoveryService> logger)
    {
        _configuration = configuration;
        _logger = logger;
    }

    public List<DiscoveredPermission> Discover()
    {
        var allowedAssemblies = _configuration
            .GetSection("Permissions:ScanAssemblies")
            .Get<string[]>() ?? new[] { Assembly.GetEntryAssembly()?.GetName().Name ?? "" };

        var discovered = new List<DiscoveredPermission>();

        foreach (var assemblyName in allowedAssemblies)
        {
            if (string.IsNullOrWhiteSpace(assemblyName))
                continue;

            Assembly? assembly = null;
            try
            {
                assembly = Assembly.Load(assemblyName);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Could not load assembly '{Assembly}' for permission scanning. Skipping.", assemblyName);
                continue;
            }

            var controllers = assembly.GetTypes()
                .Where(t => t.IsClass && !t.IsAbstract &&
                            t.CustomAttributes.Any(a => RequireAttrNames.Contains(a.AttributeType.Name)));

            foreach (var controller in controllers)
            {
                var methods = controller.GetMethods(BindingFlags.Instance | BindingFlags.Public | BindingFlags.DeclaredOnly);
                foreach (var method in methods)
                {
                    var attributes = method.CustomAttributes
                        .Where(a => RequireAttrNames.Contains(a.AttributeType.Name));
                    foreach (var attr in attributes)
                    {
                        var module = GetCtorArg<string>(attr, 0) ?? "";
                        var action = GetCtorArg<string>(attr, 1) ?? "";
                        discovered.Add(new DiscoveredPermission
                        {
                            Code = $"{module}.{action}",
                            Module = module,
                            Action = action,
                            DisplayName = GetNamedArg<string>(attr, "DisplayName"),
                            Description = GetNamedArg<string>(attr, "Description"),
                            Risk = GetNamedArg<Enum>(attr, "Risk")?.ToString() ?? "Normal",
                            ForceLiveCheck = GetNamedArg<bool>(attr, "ForceLiveCheck")
                        });
                    }
                }
            }

            foreach (var type in assembly.GetTypes().Where(t => t.IsClass && !t.IsAbstract))
            {
                var methods = type.GetMethods(BindingFlags.Instance | BindingFlags.Public | BindingFlags.DeclaredOnly);
                foreach (var method in methods)
                {
                    var anyAttrs = method.CustomAttributes
                        .Where(a => RequireAnyAttrNames.Contains(a.AttributeType.Name));
                    foreach (var attr in anyAttrs)
                    {
                        var codes = GetCtorArgStringArray(attr, 0);
                        if (codes == null) continue;
                        foreach (var code in codes)
                        {
                            var parts = code.Split('.');
                            if (parts.Length >= 2)
                            {
                                discovered.Add(new DiscoveredPermission
                                {
                                    Code = code,
                                    Module = parts[0],
                                    Action = string.Join(".", parts.Skip(1)),
                                    DisplayName = GetNamedArg<string>(attr, "DisplayName"),
                                    Description = GetNamedArg<string>(attr, "Description"),
                                    Risk = GetNamedArg<Enum>(attr, "Risk")?.ToString() ?? "Normal",
                                    ForceLiveCheck = GetNamedArg<bool>(attr, "ForceLiveCheck")
                                });
                            }
                        }
                    }
                }
            }
        }

        discovered = discovered
            .GroupBy(d => d.Code)
            .Select(g => g.First())
            .ToList();

        _logger.LogInformation("Discovered {Count} unique permissions across {AssemblyCount} assemblies",
            discovered.Count, allowedAssemblies.Length);

        return discovered;
    }

    private static T? GetCtorArg<T>(CustomAttributeData attr, int index)
    {
        if (index < attr.ConstructorArguments.Count)
            return (T?)attr.ConstructorArguments[index].Value;
        return default;
    }

    private static string[]? GetCtorArgStringArray(CustomAttributeData attr, int index)
    {
        if (index >= attr.ConstructorArguments.Count)
            return null;
        var arg = attr.ConstructorArguments[index];
        if (arg.Value is not IEnumerable<CustomAttributeTypedArgument> items)
            return null;
        return items.Select(x => x.Value?.ToString()).Where(x => x != null).Cast<string>().ToArray();
    }

    private static T? GetNamedArg<T>(CustomAttributeData attr, string name)
    {
        var named = attr.NamedArguments.FirstOrDefault(n => n.MemberName == name);
        if (named.TypedValue.Value is T val)
            return val;
        return default;
    }
}

public class DiscoveredPermission
{
    public string Code { get; set; } = string.Empty;
    public string Module { get; set; } = string.Empty;
    public string Action { get; set; } = string.Empty;
    public string? DisplayName { get; set; }
    public string? Description { get; set; }
    public string Risk { get; set; } = "Normal";
    public bool ForceLiveCheck { get; set; }
}
""";
    }

    // ═══════════════════════════════════════════════════════════════
    //  INFRASTRUCTURE LAYER — PERMISSION SYNC SERVICE
    // ═══════════════════════════════════════════════════════════════

    public static string PermissionSyncServiceClass(ProjectOptions o)
    {
        var p = P(o);
        return $$"""
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using {{p}}.Application.Authorization;
using {{p}}.Application.DTOs.Permission;
using {{p}}.Domain.Entities;
using {{p}}.Infrastructure.Persistence;

namespace {{p}}.Infrastructure.Authorization;

public class PermissionSyncService
{
    private readonly AppDbContext _db;
    private readonly ILogger<PermissionSyncService> _logger;

    public PermissionSyncService(AppDbContext db, ILogger<PermissionSyncService> logger)
    {
        _db = db;
        _logger = logger;
    }

    /// <summary>
    /// Syncs discovered permissions from code into the database.
    /// New → INSERT. Existing with changes → UPDATE + log semantic drift.
    /// Missing → IsOrphaned = true (never auto-delete).
    /// </summary>
    public async Task<PermissionSyncResultDto> SyncAsync(
        List<DiscoveredPermission> discovered,
        string? sourceCommitSha = null)
    {
        var result = new PermissionSyncResultDto();
        var changeLogs = new List<PermissionChangeLog>();

        foreach (var discoveredPerm in discovered)
        {
            var existing = await _db.Set<Permission>()
                .FirstOrDefaultAsync(p => p.Code == discoveredPerm.Code);

            if (existing == null)
            {
                // New permission: INSERT
                var permission = new Permission
                {
                    Code = discoveredPerm.Code,
                    Module = discoveredPerm.Module,
                    Action = discoveredPerm.Action,
                    DisplayName = discoveredPerm.DisplayName,
                    Description = discoveredPerm.Description,
                    Risk = discoveredPerm.Risk,
                    ForceLiveCheck = discoveredPerm.ForceLiveCheck,
                    IsOrphaned = false,
                    CreatedAt = DateTime.UtcNow,
                    UpdatedAt = DateTime.UtcNow
                };
                _db.Set<Permission>().Add(permission);
                result.Inserted++;
            }
            else
            {
                // CRITICAL SECURITY FIX (semantic drift): Compare metadata
                // against stored values. If ANY differ, update and log the
                // change. A developer can change what an existing permission
                // code actually protects without renaming it, silently
                // expanding privileges of every role that holds it.
                var hasChanges = false;

                if ((discoveredPerm.DisplayName ?? "") != (existing.DisplayName ?? "") ||
                    (discoveredPerm.Description ?? "") != (existing.Description ?? "") ||
                    discoveredPerm.Risk != existing.Risk)
                {
                    hasChanges = true;
                    var changeLog = new PermissionChangeLog
                    {
                        PermissionCode = existing.Code,
                        OldDisplayName = existing.DisplayName,
                        NewDisplayName = discoveredPerm.DisplayName,
                        OldDescription = existing.Description,
                        NewDescription = discoveredPerm.Description,
                        OldRisk = existing.Risk,
                        NewRisk = discoveredPerm.Risk,
                        ChangedAt = DateTime.UtcNow,
                        SourceCommitSha = sourceCommitSha
                    };
                    changeLogs.Add(changeLog);
                    _db.Set<PermissionChangeLog>().Add(changeLog);
                }

                if (discoveredPerm.ForceLiveCheck != existing.ForceLiveCheck)
                {
                    hasChanges = true;
                }

                if (existing.IsOrphaned)
                {
                    hasChanges = true;
                    existing.IsOrphaned = false;
                }

                if (hasChanges)
                {
                    existing.DisplayName = discoveredPerm.DisplayName;
                    existing.Description = discoveredPerm.Description;
                    existing.Risk = discoveredPerm.Risk;
                    existing.ForceLiveCheck = discoveredPerm.ForceLiveCheck;
                    existing.UpdatedAt = DateTime.UtcNow;
                    result.Updated++;
                }
                else
                {
                    result.Unchanged++;
                }
            }
        }

        // Mark orphaned: codes in DB but not in discovered set
        var discoveredCodes = new HashSet<string>(discovered.Select(d => d.Code));
        var orphaned = await _db.Set<Permission>()
            .Where(p => !discoveredCodes.Contains(p.Code) && !p.IsOrphaned)
            .ToListAsync();

        foreach (var orphan in orphaned)
        {
            orphan.IsOrphaned = true;
            orphan.UpdatedAt = DateTime.UtcNow;
            result.Orphaned++;
        }

        await _db.SaveChangesAsync();

        result.ChangeLogs = changeLogs.Select(cl => new PermissionChangeLogDto
        {
            PermissionCode = cl.PermissionCode,
            OldDisplayName = cl.OldDisplayName,
            NewDisplayName = cl.NewDisplayName,
            OldDescription = cl.OldDescription,
            NewDescription = cl.NewDescription,
            OldRisk = cl.OldRisk,
            NewRisk = cl.NewRisk,
            ChangedAt = cl.ChangedAt,
            SourceCommitSha = cl.SourceCommitSha
        }).ToList();

        _logger.LogInformation(
            "Permission sync complete. Inserted={Inserted} Updated={Updated} Orphaned={Orphaned} Unchanged={Unchanged} DriftLogged={DriftCount}",
            result.Inserted, result.Updated, result.Orphaned, result.Unchanged, result.ChangeLogs.Count);

        return result;
    }

    /// <summary>
    /// Dry-run of SyncAsync — detects what WOULD change without applying.
    /// </summary>
    public async Task<PermissionSyncResultDto> DiffAsync(List<DiscoveredPermission> discovered)
    {
        var result = new PermissionSyncResultDto();

        foreach (var discoveredPerm in discovered)
        {
            var existing = await _db.Set<Permission>()
                .FirstOrDefaultAsync(p => p.Code == discoveredPerm.Code);

            if (existing == null)
            {
                result.Inserted++;
            }
            else
            {
                // CRITICAL SECURITY FIX (semantic drift): Check for metadata
                // changes. The diff MUST report these differently from
                // new/orphaned so CI/CD pipelines fail loudly on drift.
                var hasChanges = (discoveredPerm.DisplayName ?? "") != (existing.DisplayName ?? "") ||
                                 (discoveredPerm.Description ?? "") != (existing.Description ?? "") ||
                                 discoveredPerm.Risk != existing.Risk;

                if (hasChanges)
                {
                    result.Updated++;
                    result.ChangeLogs.Add(new PermissionChangeLogDto
                    {
                        PermissionCode = existing.Code,
                        OldDisplayName = existing.DisplayName,
                        NewDisplayName = discoveredPerm.DisplayName,
                        OldDescription = existing.Description,
                        NewDescription = discoveredPerm.Description,
                        OldRisk = existing.Risk,
                        NewRisk = discoveredPerm.Risk
                    });
                }
                else
                {
                    result.Unchanged++;
                }
            }
        }

        var discoveredCodes = new HashSet<string>(discovered.Select(d => d.Code));
        var orphanedCount = await _db.Set<Permission>()
            .CountAsync(p => !discoveredCodes.Contains(p.Code) && !p.IsOrphaned);
        result.Orphaned = orphanedCount;

        return result;
    }

    public async Task<List<PermissionChangeLogDto>> GetChangeLogAsync()
    {
        var logs = await _db.Set<PermissionChangeLog>()
            .OrderByDescending(cl => cl.ChangedAt)
            .Take(500)
            .ToListAsync();

        return logs.Select(cl => new PermissionChangeLogDto
        {
            PermissionCode = cl.PermissionCode,
            OldDisplayName = cl.OldDisplayName,
            NewDisplayName = cl.NewDisplayName,
            OldDescription = cl.OldDescription,
            NewDescription = cl.NewDescription,
            OldRisk = cl.OldRisk,
            NewRisk = cl.NewRisk,
            ChangedAt = cl.ChangedAt,
            SourceCommitSha = cl.SourceCommitSha
        }).ToList();
    }

    public async Task PruneAsync()
    {
        var orphaned = await _db.Set<Permission>()
            .Where(p => p.IsOrphaned)
            .ToListAsync();

        // Delete RolePermission links
        var permissionIds = orphaned.Select(p => p.Id).ToList();
        var rolePerms = await _db.Set<RolePermission>()
            .Where(rp => permissionIds.Contains(rp.PermissionId))
            .ToListAsync();
        _db.Set<RolePermission>().RemoveRange(rolePerms);

        // Delete UserPermission links
        var userPerms = await _db.Set<UserPermission>()
            .Where(up => permissionIds.Contains(up.PermissionId))
            .ToListAsync();
        _db.Set<UserPermission>().RemoveRange(userPerms);

        // Delete orphaned permissions
        _db.Set<Permission>().RemoveRange(orphaned);

        await _db.SaveChangesAsync();

        _logger.LogInformation("Pruned {Count} orphaned permissions and their links.", orphaned.Count);
    }
}
""";
    }

    // ═══════════════════════════════════════════════════════════════
    //  INFRASTRUCTURE LAYER — PERMISSION MANAGEMENT SERVICE
    // ═══════════════════════════════════════════════════════════════

    public static string PermissionManagementServiceClass(ProjectOptions o)
    {
        var p = P(o);
        var rawMgmtRoleLookupIdentity = """
        var userRoles = await _db.UserRoles
            .Where(ur => ur.UserId == userId)
            .Select(ur => ur.RoleId)
            .ToListAsync();
""";
        var rawMgmtRoleLookupCustomJwt = """
        // CustomJwt: no Identity UserRoles — skip role-based check
        var userRoles = new List<string>();
""";
        var rawSyncGrantToSuperAdmin = """
        // Optionally grant new permissions to SuperAdmin
        if (grantNewToSuperAdmin && result.Inserted > 0)
        {
            var superAdminRole = await _db.Roles
                .OfType<ApplicationRole>()
                .FirstOrDefaultAsync(r => r.Name == "SuperAdmin" && r.IsSystemRole);

            if (superAdminRole != null)
            {
                var newPerms = await _db.Set<Permission>()
                    .OrderByDescending(p => p.CreatedAt)
                    .Take(result.Inserted)
                    .ToListAsync();

                foreach (var perm in newPerms)
                {
                    var existing = await _db.Set<RolePermission>()
                        .FirstOrDefaultAsync(rp => rp.RoleId == superAdminRole.Id && rp.PermissionId == perm.Id);
                    if (existing == null)
                    {
                        _db.Set<RolePermission>().Add(new RolePermission
                        {
                            RoleId = superAdminRole.Id,
                            PermissionId = perm.Id
                        });
                    }
                }
                await _db.SaveChangesAsync();
                _logger.LogInformation("Granted {Count} new permissions to SuperAdmin role.", newPerms.Count);
            }
        }
""";
        var rawSyncGrantToSuperAdminCustomJwt = """
        // CustomJwt: SuperAdmin role is Identity-only — skip grant to SuperAdmin
        if (grantNewToSuperAdmin && result.Inserted > 0)
        {
            _logger.LogWarning("grantNewToSuperAdmin is not supported in CustomJwt mode (no Identity RoleManager).");
        }
""";
        return $$"""
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using {{p}}.Application.Authorization;
using {{p}}.Application.DTOs.Permission;
using {{p}}.Domain.Entities;
using {{p}}.Domain.Enums;
using {{p}}.Domain.Exceptions;
using {{p}}.Infrastructure.Persistence;

namespace {{p}}.Infrastructure.Authorization;

public class PermissionManagementService : IPermissionManagementService
{
    private readonly AppDbContext _db;
    private readonly IPermissionCache _cache;
    private readonly PermissionSyncService _syncService;
    private readonly ILogger<PermissionManagementService> _logger;

    public PermissionManagementService(
        AppDbContext db,
        IPermissionCache cache,
        PermissionSyncService syncService,
        ILogger<PermissionManagementService> logger)
    {
        _db = db;
        _cache = cache;
        _syncService = syncService;
        _logger = logger;
    }

    public async Task<List<PermissionDto>> GetAllPermissionsAsync()
    {
        return await _db.Set<Permission>()
            .OrderBy(p => p.Module)
            .ThenBy(p => p.Action)
            .Select(p => new PermissionDto
            {
                Id = p.Id,
                Code = p.Code,
                Module = p.Module,
                Action = p.Action,
                DisplayName = p.DisplayName,
                Description = p.Description,
                Risk = p.Risk,
                IsOrphaned = p.IsOrphaned
            })
            .ToListAsync();
    }

    public async Task<PermissionDto?> GetPermissionByCodeAsync(string code)
    {
        var p = await _db.Set<Permission>().FirstOrDefaultAsync(x => x.Code == code);
        if (p == null) return null;
        return new PermissionDto
        {
            Id = p.Id,
            Code = p.Code,
            Module = p.Module,
            Action = p.Action,
            DisplayName = p.DisplayName,
            Description = p.Description,
            Risk = p.Risk,
            IsOrphaned = p.IsOrphaned
        };
    }

    public async Task GrantPermissionToRoleAsync(string roleId, string permissionCode)
    {
        // CRITICAL SECURITY FIX: Permissions can only be discovered from code.
        // There is NO endpoint to create a permission by arbitrary string.
        var permission = await _db.Set<Permission>().FirstOrDefaultAsync(p => p.Code == permissionCode)
            ?? throw new PermissionNotFoundException(permissionCode);

        using var transaction = await _db.Database.BeginTransactionAsync();

        var existing = await _db.Set<RolePermission>()
            .FirstOrDefaultAsync(rp => rp.RoleId == roleId && rp.PermissionId == permission.Id);

        if (existing != null)
        {
            await transaction.RollbackAsync();
            return; // Already granted
        }

        var rolePermission = new RolePermission
        {
            RoleId = roleId,
            PermissionId = permission.Id
        };
        _db.Set<RolePermission>().Add(rolePermission);

        // Invalidate cache for all users in this role
        await InvalidateCacheForRoleAsync(roleId);

        await _db.SaveChangesAsync();
        await transaction.CommitAsync();

        _logger.LogInformation("Granted permission '{PermissionCode}' to role '{RoleId}'", permissionCode, roleId);
    }

    public async Task RevokePermissionFromRoleAsync(string roleId, string permissionCode)
    {
        var permission = await _db.Set<Permission>().FirstOrDefaultAsync(p => p.Code == permissionCode)
            ?? throw new PermissionNotFoundException(permissionCode);

        // CRITICAL SECURITY FIX: Check if this is the last role/user holding
        // any Critical-risk permission before allowing the revocation.
        await EnsureNotLastCriticalHolderAsync(roleId, permission.Id, null);

        using var transaction = await _db.Database.BeginTransactionAsync();

        var rolePermission = await _db.Set<RolePermission>()
            .FirstOrDefaultAsync(rp => rp.RoleId == roleId && rp.PermissionId == permission.Id);

        if (rolePermission == null)
        {
            await transaction.RollbackAsync();
            return; // Not granted
        }

        _db.Set<RolePermission>().Remove(rolePermission);

        await InvalidateCacheForRoleAsync(roleId);

        await _db.SaveChangesAsync();
        await transaction.CommitAsync();

        _logger.LogInformation("Revoked permission '{PermissionCode}' from role '{RoleId}'", permissionCode, roleId);
    }

    public async Task<List<string>> GetRolePermissionsAsync(string roleId)
    {
        return await _db.Set<RolePermission>()
            .Where(rp => rp.RoleId == roleId)
            .Include(rp => rp.Permission)
            .Select(rp => rp.Permission.Code)
            .ToListAsync();
    }

    public async Task SetUserPermissionOverrideAsync(string userId, string permissionCode, bool isGranted)
    {
        var permission = await _db.Set<Permission>().FirstOrDefaultAsync(p => p.Code == permissionCode)
            ?? throw new PermissionNotFoundException(permissionCode);

        using var transaction = await _db.Database.BeginTransactionAsync();

        var existing = await _db.Set<UserPermission>()
            .FirstOrDefaultAsync(up => up.UserId == userId && up.PermissionId == permission.Id);

        if (existing != null)
        {
            existing.IsGranted = isGranted;
        }
        else
        {
            var userPermission = new UserPermission
            {
                UserId = userId,
                PermissionId = permission.Id,
                IsGranted = isGranted
            };
            _db.Set<UserPermission>().Add(userPermission);
        }

        // Invalidate single-user cache
        await _cache.RemoveAsync(userId);

        await _db.SaveChangesAsync();
        await transaction.CommitAsync();
    }

    public async Task RemoveUserPermissionOverrideAsync(string userId, string permissionCode)
    {
        var permission = await _db.Set<Permission>().FirstOrDefaultAsync(p => p.Code == permissionCode)
            ?? throw new PermissionNotFoundException(permissionCode);

        using var transaction = await _db.Database.BeginTransactionAsync();

        var existing = await _db.Set<UserPermission>()
            .FirstOrDefaultAsync(up => up.UserId == userId && up.PermissionId == permission.Id);

        if (existing != null)
        {
            _db.Set<UserPermission>().Remove(existing);
            await _cache.RemoveAsync(userId);
            await _db.SaveChangesAsync();
        }

        await transaction.CommitAsync();
    }

    public async Task<List<PermissionDto>> GetEffectivePermissionsAsync(string userId)
    {
        // Get role-derived permissions
{{(o.AuthType == AuthType.IdentityWithJwt ? rawMgmtRoleLookupIdentity : rawMgmtRoleLookupCustomJwt)}}

        var rolePermissionCodes = await _db.Set<RolePermission>()
            .Where(rp => userRoles.Contains(rp.RoleId))
            .Include(rp => rp.Permission)
            .Select(rp => rp.Permission.Code)
            .ToListAsync();

        // Get user overrides
        var userPermissions = await _db.Set<UserPermission>()
            .Where(up => up.UserId == userId)
            .Include(up => up.Permission)
            .ToListAsync();

        var result = new List<PermissionDto>();

        // Add role-derived permissions (unless denied by user override)
        foreach (var code in rolePermissionCodes)
        {
            var userOverride = userPermissions.FirstOrDefault(up => up.Permission.Code == code);
            if (userOverride != null && !userOverride.IsGranted)
                continue; // Explicitly denied by user override

            var perm = await _db.Set<Permission>().FirstOrDefaultAsync(p => p.Code == code);
            if (perm != null)
            {
                result.Add(new PermissionDto
                {
                    Id = perm.Id,
                    Code = perm.Code,
                    Module = perm.Module,
                    Action = perm.Action,
                    DisplayName = perm.DisplayName,
                    Description = perm.Description,
                    Risk = perm.Risk,
                    IsOrphaned = perm.IsOrphaned
                });
            }
        }

        // Add granted user overrides that are not already included
        foreach (var up in userPermissions.Where(u => u.IsGranted))
        {
            if (!result.Any(r => r.Code == up.Permission.Code))
            {
                result.Add(new PermissionDto
                {
                    Id = up.Permission.Id,
                    Code = up.Permission.Code,
                    Module = up.Permission.Module,
                    Action = up.Permission.Action,
                    DisplayName = up.Permission.DisplayName,
                    Description = up.Permission.Description,
                    Risk = up.Permission.Risk,
                    IsOrphaned = up.Permission.IsOrphaned
                });
            }
        }

        return result;
    }

    public async Task<PermissionSyncResultDto> SyncPermissionsAsync(
        List<(string Code, string Module, string Action, string? DisplayName, string? Description, string Risk, bool ForceLiveCheck)> discoveredPermissions,
        bool grantNewToSuperAdmin = false,
        string? sourceCommitSha = null)
    {
        var discovered = discoveredPermissions
            .Select(d => new DiscoveredPermission
            {
                Code = d.Code,
                Module = d.Module,
                Action = d.Action,
                DisplayName = d.DisplayName,
                Description = d.Description,
                Risk = d.Risk,
                ForceLiveCheck = d.ForceLiveCheck
            })
            .ToList();

        var result = await _syncService.SyncAsync(discovered, sourceCommitSha);

{{(o.AuthType == AuthType.IdentityWithJwt ? rawSyncGrantToSuperAdmin : rawSyncGrantToSuperAdminCustomJwt)}}

        return result;
    }

    public async Task<PermissionSyncResultDto> DiffPermissionsAsync(
        List<(string Code, string Module, string Action, string? DisplayName, string? Description, string Risk, bool ForceLiveCheck)> discoveredPermissions)
    {
        var discovered = discoveredPermissions
            .Select(d => new DiscoveredPermission
            {
                Code = d.Code,
                Module = d.Module,
                Action = d.Action,
                DisplayName = d.DisplayName,
                Description = d.Description,
                Risk = d.Risk,
                ForceLiveCheck = d.ForceLiveCheck
            })
            .ToList();

        return await _syncService.DiffAsync(discovered);
    }

    public async Task<List<PermissionChangeLogDto>> GetChangeLogAsync()
    {
        return await _syncService.GetChangeLogAsync();
    }

    public async Task PruneOrphanedPermissionsAsync()
    {
        await _syncService.PruneAsync();
    }

    public async Task<PermissionAuditLog> WriteAuditLogAsync(
        string actorUserId, string targetType, string targetId,
        string permissionCode, string action, string? actorIpAddress)
    {
        var auditLog = new PermissionAuditLog
        {
            ActorUserId = actorUserId,
            TargetType = targetType,
            TargetId = targetId,
            PermissionCode = permissionCode,
            Action = action,
            Timestamp = DateTime.UtcNow,
            ActorIpAddress = actorIpAddress
        };
        _db.Set<PermissionAuditLog>().Add(auditLog);
        await _db.SaveChangesAsync();
        return auditLog;
    }

    // ── Private helpers ────────────────────────────────────────

    /// <summary>
    /// CRITICAL SECURITY FIX: Generalized last-critical-permission-holder guard.
    /// Checks ANY permission marked Risk = Critical, not just permissions.manage
    /// by name — so this safeguard automatically covers future critical
    /// permissions without code changes.
    /// </summary>
    private async Task EnsureNotLastCriticalHolderAsync(string roleId, string permissionId, string? userId)
    {
        var permission = await _db.Set<Permission>().FindAsync(permissionId);
        if (permission == null) return;

        // Only enforce for Critical-risk permissions
        if (!Enum.TryParse<PermissionRisk>(permission.Risk, out var risk) || risk != PermissionRisk.Critical)
            return;

        if (userId == null)
        {
            // Check role-level: is this the last role holding this critical permission?
            var otherRolesWithThisPerm = await _db.Set<RolePermission>()
                .CountAsync(rp => rp.PermissionId == permissionId && rp.RoleId != roleId);

            if (otherRolesWithThisPerm == 0)
            {
                // Also check user-level overrides
                var userOverrides = await _db.Set<UserPermission>()
                    .CountAsync(up => up.PermissionId == permissionId && up.IsGranted);

                if (userOverrides == 0)
                {
                    throw new InvalidOperationException(
                        $"Cannot revoke critical permission '{permission.Code}': " +
                        "this is the last holder. At least one role or user must retain this permission.");
                }
            }
        }
    }

    private async Task InvalidateCacheForRoleAsync(string roleId)
    {
        await _cache.RemoveByRoleAsync(roleId);
    }
}
""";
    }

    // ═══════════════════════════════════════════════════════════════
    //  INFRASTRUCTURE LAYER — ROLE MANAGEMENT SERVICE
    // ═══════════════════════════════════════════════════════════════

    public static string RoleManagementServiceClass(ProjectOptions o)
    {
        var p = P(o);
        return $$"""
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using {{p}}.Application.Authorization;
using {{p}}.Application.DTOs.Permission;
using {{p}}.Domain.Entities;
using {{p}}.Infrastructure.Persistence;

namespace {{p}}.Infrastructure.Authorization;

public class RoleManagementService : IRoleManagementService
{
    private readonly RoleManager<ApplicationRole> _roleManager;
    private readonly UserManager<AppUser> _userManager;
    private readonly AppDbContext _db;
    private readonly IPermissionCache _cache;
    private readonly ILogger<RoleManagementService> _logger;

    public RoleManagementService(
        RoleManager<ApplicationRole> roleManager,
        UserManager<AppUser> userManager,
        AppDbContext db,
        IPermissionCache cache,
        ILogger<RoleManagementService> logger)
    {
        _roleManager = roleManager;
        _userManager = userManager;
        _db = db;
        _cache = cache;
        _logger = logger;
    }

    public async Task<List<RoleDto>> GetAllRolesAsync()
    {
        var roles = await _roleManager.Roles.ToListAsync();
        var result = new List<RoleDto>();

        foreach (var role in roles)
        {
            var userCount = await _db.UserRoles.CountAsync(ur => ur.RoleId == role.Id);
            var permissions = await _db.Set<RolePermission>()
                .Where(rp => rp.RoleId == role.Id)
                .Include(rp => rp.Permission)
                .Select(rp => rp.Permission.Code)
                .ToListAsync();

            result.Add(new RoleDto
            {
                Id = role.Id,
                Name = role.Name ?? "",
                Description = role is ApplicationRole appRole ? appRole.Description : null,
                IsSystemRole = role is ApplicationRole appRole2 && appRole2.IsSystemRole,
                UserCount = userCount,
                Permissions = permissions
            });
        }

        return result;
    }

    public async Task<RoleDto> CreateRoleAsync(string name, string? description, string actorUserId, string? actorIpAddress = null)
    {
        // Role creation does not auto-grant any permissions — no implicit trust.
        var role = new ApplicationRole
        {
            Name = name,
            Description = description,
            IsSystemRole = false
        };

        var result = await _roleManager.CreateAsync(role);
        if (!result.Succeeded)
        {
            var errors = string.Join("; ", result.Errors.Select(e => e.Description));
            throw new InvalidOperationException($"Failed to create role: {errors}");
        }

        // Audit log
        _db.Set<RoleAuditLog>().Add(new RoleAuditLog
        {
            ActorUserId = actorUserId,
            Action = "Created",
            TargetRoleId = role.Id,
            Details = $"Role '{name}' created",
            Timestamp = DateTime.UtcNow
        });
        await _db.SaveChangesAsync();

        _logger.LogInformation("Role '{RoleName}' created by '{ActorUserId}'", name, actorUserId);

        return new RoleDto
        {
            Id = role.Id,
            Name = role.Name,
            Description = role.Description,
            IsSystemRole = role.IsSystemRole,
            UserCount = 0,
            Permissions = new List<string>()
        };
    }

    public async Task RenameRoleAsync(string roleId, string newName, string actorUserId, string? actorIpAddress = null)
    {
        var role = await _roleManager.FindByIdAsync(roleId)
            ?? throw new InvalidOperationException($"Role with ID '{roleId}' not found.");

        // CRITICAL SECURITY FIX: System roles cannot be renamed.
        if (role.IsSystemRole)
            throw new InvalidOperationException($"System role '{role.Name}' cannot be renamed.");

        var oldName = role.Name;
        role.Name = newName;

        var result = await _roleManager.UpdateAsync(role);
        if (!result.Succeeded)
        {
            var errors = string.Join("; ", result.Errors.Select(e => e.Description));
            throw new InvalidOperationException($"Failed to rename role: {errors}");
        }

        // Audit log — renaming does NOT change Id, so permission/user relationships are safe
        _db.Set<RoleAuditLog>().Add(new RoleAuditLog
        {
            ActorUserId = actorUserId,
            Action = "Renamed",
            TargetRoleId = role.Id,
            Details = $"Role renamed from '{oldName}' to '{newName}'",
            Timestamp = DateTime.UtcNow
        });
        await _db.SaveChangesAsync();

        _logger.LogInformation("Role '{RoleId}' renamed from '{OldName}' to '{NewName}' by '{ActorUserId}'",
            roleId, oldName, newName, actorUserId);
    }

    public async Task DeleteRoleAsync(string roleId, string actorUserId, string? actorIpAddress = null)
    {
        var role = await _roleManager.FindByIdAsync(roleId)
            ?? throw new InvalidOperationException($"Role with ID '{roleId}' not found.");

        // CRITICAL SECURITY FIX: System roles cannot be deleted.
        if (role.IsSystemRole)
            throw new InvalidOperationException($"System role '{role.Name}' cannot be deleted.");

        // CRITICAL SECURITY FIX: Cannot delete a role that is currently assigned to any user.
        var userCount = await _db.UserRoles.CountAsync(ur => ur.RoleId == roleId);
        if (userCount > 0)
        {
            throw new InvalidOperationException(
                $"Cannot delete role '{role.Name}' because it is currently assigned to {userCount} user(s). " +
                "Reassign or remove all users from this role first.");
        }

        // CRITICAL SECURITY FIX: Check that deleting this role doesn't strip
        // the last holder of any Critical-risk permission.
        var rolePerms = await _db.Set<RolePermission>()
            .Where(rp => rp.RoleId == roleId)
            .Include(rp => rp.Permission)
            .ToListAsync();

        foreach (var rp in rolePerms)
        {
            if (Enum.TryParse<Domain.Enums.PermissionRisk>(rp.Permission.Risk, out var risk) && risk == Domain.Enums.PermissionRisk.Critical)
            {
                var otherHolders = await _db.Set<RolePermission>()
                    .CountAsync(x => x.PermissionId == rp.PermissionId && x.RoleId != roleId);
                var userOverrides = await _db.Set<UserPermission>()
                    .CountAsync(up => up.PermissionId == rp.PermissionId && up.IsGranted);

                if (otherHolders == 0 && userOverrides == 0)
                {
                    throw new InvalidOperationException(
                        $"Cannot delete role '{role.Name}': it is the last holder of critical permission '{rp.Permission.Code}'. " +
                        "Transfer this permission to another role or user first.");
                }
            }
        }

        // Remove all role-permission links
        _db.Set<RolePermission>().RemoveRange(rolePerms);

        // Remove the role
        var result = await _roleManager.DeleteAsync(role);
        if (!result.Succeeded)
        {
            var errors = string.Join("; ", result.Errors.Select(e => e.Description));
            throw new InvalidOperationException($"Failed to delete role: {errors}");
        }

        // Invalidate cache for all affected users
        await _cache.RemoveByRoleAsync(roleId);

        // Audit log
        _db.Set<RoleAuditLog>().Add(new RoleAuditLog
        {
            ActorUserId = actorUserId,
            Action = "Deleted",
            TargetRoleId = roleId,
            Details = $"Role '{role.Name}' deleted",
            Timestamp = DateTime.UtcNow
        });
        await _db.SaveChangesAsync();

        _logger.LogInformation("Role '{RoleName}' ({RoleId}) deleted by '{ActorUserId}'", role.Name, roleId, actorUserId);
    }

    public async Task AssignUserToRoleAsync(string userId, string roleId, string actorUserId, string? actorIpAddress = null)
    {
        var role = await _roleManager.FindByIdAsync(roleId)
            ?? throw new InvalidOperationException($"Role with ID '{roleId}' not found.");

        var user = await _userManager.FindByIdAsync(userId);
        if (user == null)
            throw new InvalidOperationException($"User with ID '{userId}' not found.");

        var result = await _userManager.AddToRoleAsync(user, role.Name!);
        if (!result.Succeeded)
        {
            var errors = string.Join("; ", result.Errors.Select(e => e.Description));
            throw new InvalidOperationException($"Failed to assign user to role: {errors}");
        }

        // Invalidate cache for this user
        await _cache.RemoveAsync(userId);

        // Audit log
        _db.Set<RoleAuditLog>().Add(new RoleAuditLog
        {
            ActorUserId = actorUserId,
            Action = "UserAssigned",
            TargetRoleId = roleId,
            TargetUserId = userId,
            Details = $"User '{userId}' assigned to role '{role.Name}'",
            Timestamp = DateTime.UtcNow
        });
        await _db.SaveChangesAsync();

        // Track in cache
        if (_cache is PermissionCache pc)
        {
            pc.TrackUserRole(userId, roleId);
        }

        _logger.LogInformation("User '{UserId}' assigned to role '{RoleName}' by '{ActorUserId}'",
            userId, role.Name, actorUserId);
    }

    public async Task RemoveUserFromRoleAsync(string userId, string roleId, string actorUserId, string? actorIpAddress = null)
    {
        var role = await _roleManager.FindByIdAsync(roleId)
            ?? throw new InvalidOperationException($"Role with ID '{roleId}' not found.");

        var user = await _userManager.FindByIdAsync(userId);
        if (user == null)
            throw new InvalidOperationException($"User with ID '{userId}' not found.");

        var result = await _userManager.RemoveFromRoleAsync(user, role.Name!);
        if (!result.Succeeded)
        {
            var errors = string.Join("; ", result.Errors.Select(e => e.Description));
            throw new InvalidOperationException($"Failed to remove user from role: {errors}");
        }

        // Invalidate cache for this user
        await _cache.RemoveAsync(userId);

        // Audit log
        _db.Set<RoleAuditLog>().Add(new RoleAuditLog
        {
            ActorUserId = actorUserId,
            Action = "UserRemoved",
            TargetRoleId = roleId,
            TargetUserId = userId,
            Details = $"User '{userId}' removed from role '{role.Name}'",
            Timestamp = DateTime.UtcNow
        });
        await _db.SaveChangesAsync();

        _logger.LogInformation("User '{UserId}' removed from role '{RoleName}' by '{ActorUserId}'",
            userId, role.Name, actorUserId);
    }

    public async Task<List<UserDto>> GetUsersInRoleAsync(string roleId)
    {
        var role = await _roleManager.FindByIdAsync(roleId);
        if (role == null)
            throw new InvalidOperationException($"Role with ID '{roleId}' not found.");

        var users = await _userManager.GetUsersInRoleAsync(role.Name!);
        return users.Select(u => new UserDto
        {
            Id = u.Id,
            UserName = u.UserName ?? "",
            Email = u.Email ?? ""
        }).ToList();
    }
}
""";
    }

    // ═══════════════════════════════════════════════════════════════
    //  INFRASTRUCTURE LAYER — PERMISSION SEED SERVICE
    // ═══════════════════════════════════════════════════════════════

    public static string PermissionSeedServiceClass(ProjectOptions o)
    {
        var p = P(o);
        return $$"""
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using {{p}}.Domain.Entities;
using {{p}}.Infrastructure.Persistence;

namespace {{p}}.Infrastructure.Authorization;

/// <summary>
/// Seeds the SuperAdmin system role with all discovered permissions on first run.
/// Guarded by a marker row so it never re-runs.
/// </summary>
public class PermissionSeedService
{
    private readonly AppDbContext _db;
    private readonly RoleManager<ApplicationRole> _roleManager;
    private readonly PermissionDiscoveryService _discoveryService;
    private readonly PermissionSyncService _syncService;
    private readonly ILogger<PermissionSeedService> _logger;

    public PermissionSeedService(
        AppDbContext db,
        RoleManager<ApplicationRole> roleManager,
        PermissionDiscoveryService discoveryService,
        PermissionSyncService syncService,
        ILogger<PermissionSeedService> logger)
    {
        _db = db;
        _roleManager = roleManager;
        _discoveryService = discoveryService;
        _syncService = syncService;
        _logger = logger;
    }

    public async Task SeedAsync()
    {
        // Check if seeding has already been performed
        var alreadySeeded = await _db.Set<Permission>().AnyAsync();
        var superAdminExists = await _roleManager.RoleExistsAsync("SuperAdmin");

        if (alreadySeeded || superAdminExists)
            return;

        _logger.LogInformation("Running first-run seed: SuperAdmin role + all discovered permissions.");

        // 1. Discover permissions from code
        var discovered = _discoveryService.Discover();

        // 2. Sync them to database
        await _syncService.SyncAsync(discovered);

        // CRITICAL SECURITY FIX: Ensure permissions.manage and roles.manage exist.
        // If they don't, something is wrong — the controllers were removed.
        var hasPermissionsManage = discovered.Any(d => d.Code == "permissions.manage");
        var hasRolesManage = discovered.Any(d => d.Code == "roles.manage");

        if (!hasPermissionsManage || !hasRolesManage)
        {
            throw new InvalidOperationException(
                "CRITICAL SEED FAILURE: Required permission codes 'permissions.manage' and/or 'roles.manage' were not found " +
                "in the discovered set. This means the controllers protecting management endpoints have been removed or " +
                "their RequirePermission attributes are missing. The SuperAdmin role cannot be created without these permissions. " +
                "Restore the management controllers or add the RequirePermission attributes before running seed.");
        }

        // 3. Create SuperAdmin role
        var superAdmin = new ApplicationRole
        {
            Name = "SuperAdmin",
            Description = "System administrator with all permissions",
            IsSystemRole = true
        };

        var createResult = await _roleManager.CreateAsync(superAdmin);
        if (!createResult.Succeeded)
        {
            var errors = string.Join("; ", createResult.Errors.Select(e => e.Description));
            throw new InvalidOperationException($"Failed to create SuperAdmin role: {errors}");
        }

        // 4. Grant ALL discovered permissions to SuperAdmin
        var allPermissions = await _db.Set<Permission>().ToListAsync();
        foreach (var perm in allPermissions)
        {
            _db.Set<RolePermission>().Add(new RolePermission
            {
                RoleId = superAdmin.Id,
                PermissionId = perm.Id
            });
        }

        // Audit log for seed
        _db.Set<RoleAuditLog>().Add(new RoleAuditLog
        {
            ActorUserId = "SYSTEM_SEED",
            Action = "Created",
            TargetRoleId = superAdmin.Id,
            Details = "SuperAdmin system role seeded with all discovered permissions",
            Timestamp = DateTime.UtcNow
        });

        await _db.SaveChangesAsync();

        _logger.LogInformation("Seed complete. SuperAdmin role created with {PermissionCount} permissions.",
            allPermissions.Count);
    }
}
""";
    }

    // ═══════════════════════════════════════════════════════════════
    //  INFRASTRUCTURE LAYER — DI EXTENSIONS
    // ═══════════════════════════════════════════════════════════════

    public static string PermissionServiceExtensionsClass(ProjectOptions o)
    {
        var p = P(o);
        var roleMgmtReg = o.AuthType == AuthType.IdentityWithJwt
            ? "        services.AddScoped<IRoleManagementService, RoleManagementService>();\n"
            : "";
        var seedReg = o.AuthType == AuthType.IdentityWithJwt
            ? "        services.AddTransient<PermissionSeedService>();\n"
            : "";
        return $$"""
using Microsoft.Extensions.DependencyInjection;
using {{p}}.Application.Authorization;
using {{p}}.Infrastructure.Authorization;

namespace {{p}}.Infrastructure.DependencyInjection;

public static class PermissionServiceExtensions
{
    public static IServiceCollection AddPermissionServices(
        this IServiceCollection services,
        bool includeRoleManagement = true)
    {
        // Permissions cache (singleton for in-memory cache)
        services.AddSingleton<IPermissionCache, PermissionCache>();

        // Permission service (scoped per request)
        services.AddScoped<IPermissionService, PermissionService>();

        // Permission management (scoped)
        services.AddScoped<IPermissionManagementService, PermissionManagementService>();

        // Role management (scoped) — requires ASP.NET Core Identity (RoleManager).
        // Only available in IdentityWithJwt auth mode.
{{roleMgmtReg}}
        // Discovery and sync services
        services.AddSingleton<PermissionDiscoveryService>();
        services.AddScoped<PermissionSyncService>();

        // Seeding — requires ASP.NET Core Identity (RoleManager).
        // Only available in IdentityWithJwt auth mode.
{{seedReg}}
        // Resource authorization — registered open generic
        services.AddTransient(typeof(IResourceAuthorizationService<>), typeof(DefaultOwnershipResourceAuthorizationService<>));

        return services;
    }
}
""";
    }

    // ═══════════════════════════════════════════════════════════════
    //  API LAYER — FILTERS
    // ═══════════════════════════════════════════════════════════════

    public static string RequirePermissionAttributeClass(ProjectOptions o)
    {
        var p = P(o);
        return $$"""
using System.Text.RegularExpressions;
using {{p}}.Domain.Enums;
using {{p}}.Domain.Exceptions;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;

namespace {{p}}.Api.Filters;

/// <summary>
/// CRITICAL SECURITY FIX: This is a SINGLE attribute that BOTH declares
/// metadata for discovery AND actively enforces authorization. There is no
/// second [Authorize(Policy = "...")] attribute for a developer to forget.
///
/// Declaration and enforcement are unified in one attribute, eliminating
/// the most common permission-system vulnerability: documented-but-unenforced endpoints.
/// </summary>
[AttributeUsage(AttributeTargets.Method | AttributeTargets.Class, AllowMultiple = true)]
public class RequirePermissionAttribute : Attribute, IFilterFactory
{
    public string Module { get; }
    public string Action { get; }
    public string Code => $"{Module}.{Action}";
    public string? DisplayName { get; set; }
    public string? Description { get; set; }
    public PermissionRisk Risk { get; set; } = PermissionRisk.Normal;

    /// <summary>
    /// If true, this permission must NEVER be served from cache/JWT claims —
    /// always re-checked live against the database on every request.
    /// CRITICAL SECURITY FIX: Prevents stale-cache exploitation for high-impact permissions.
    /// </summary>
    public bool ForceLiveCheck { get; set; }

    public RequirePermissionAttribute(string module, string action)
    {
        Module = module.ToLowerInvariant();
        Action = action.ToLowerInvariant();

        if (!Regex.IsMatch(Code, @"^[a-z0-9]+(\.[a-z0-9]+)+$"))
            throw new InvalidPermissionCodeException(
                $"Permission code '{Code}' must follow 'module.action' format (lowercase, dot-separated).");
    }

    public bool IsReusable => false;

    public IFilterMetadata CreateInstance(IServiceProvider serviceProvider)
    {
        var filter = ActivatorUtilities.CreateInstance<RequirePermissionFilter>(serviceProvider);
        filter.SetMetadata(this);
        return filter;
    }
}
""";
    }

    public static string RequirePermissionFilterClass(ProjectOptions o)
    {
        var p = P(o);
        return $$"""
using {{p}}.Application.Authorization;
using {{p}}.Application.Extensions;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;

namespace {{p}}.Api.Filters;

/// <summary>
/// CRITICAL SECURITY FIX: This filter enforces the permission check at runtime.
/// It is created via IFilterFactory on RequirePermissionAttribute, so it can
/// use constructor DI (services can't be injected into attributes directly).
/// </summary>
public class RequirePermissionFilter : IAsyncAuthorizationFilter
{
    private RequirePermissionAttribute? _metadata;
    private readonly IPermissionService _permissionService;
    private readonly ILogger<RequirePermissionFilter> _logger;

    public RequirePermissionFilter(
        IPermissionService permissionService,
        ILogger<RequirePermissionFilter> logger)
    {
        _permissionService = permissionService;
        _logger = logger;
    }

    public void SetMetadata(RequirePermissionAttribute metadata)
    {
        _metadata = metadata;
    }

    public async Task OnAuthorizationAsync(AuthorizationFilterContext context)
    {
        if (_metadata == null)
        {
            context.Result = new ObjectResult(new { error = "Filter misconfigured: metadata not set." })
            {
                StatusCode = StatusCodes.Status500InternalServerError
            };
            return;
        }

        var user = context.HttpContext.User;

        if (user?.Identity?.IsAuthenticated != true)
        {
            context.Result = new UnauthorizedResult();
            return;
        }

        var userId = user.GetUserId();

        bool hasPermission = await _permissionService.UserHasPermissionAsync(
            userId, _metadata.Code, forceLiveCheck: _metadata.ForceLiveCheck);

        if (!hasPermission)
        {
            _logger.LogWarning(
                "Authorization denied. UserId={UserId} Permission={Permission} Path={Path}",
                userId, _metadata.Code, context.HttpContext.Request.Path);
            context.Result = new ObjectResult(new { error = "forbidden", permission = _metadata.Code })
            {
                StatusCode = StatusCodes.Status403Forbidden
            };
        }
    }
}
""";
    }

    public static string RequireAnyPermissionAttributeClass(ProjectOptions o)
    {
        var p = P(o);
        return $$"""
using System.Text.RegularExpressions;
using {{p}}.Application.Authorization;
using {{p}}.Application.Extensions;
using {{p}}.Domain.Enums;
using {{p}}.Domain.Exceptions;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;

namespace {{p}}.Api.Filters;

/// <summary>
/// OR-semantics permission check: the user needs at least ONE of the specified
/// permission codes to pass authorization. This is explicitly named so that OR
/// logic is never silently achieved by misusing AND-based attributes.
/// </summary>
[AttributeUsage(AttributeTargets.Method | AttributeTargets.Class, AllowMultiple = false)]
public class RequireAnyPermissionAttribute : Attribute, IFilterFactory
{
    public string[] PermissionCodes { get; }
    public string? DisplayName { get; set; }
    public string? Description { get; set; }
    public PermissionRisk Risk { get; set; } = PermissionRisk.Normal;
    public bool ForceLiveCheck { get; set; }

    public RequireAnyPermissionAttribute(params string[] permissionCodes)
    {
        if (permissionCodes == null || permissionCodes.Length == 0)
            throw new ArgumentException("At least one permission code is required.", nameof(permissionCodes));

        PermissionCodes = permissionCodes.Select(c => c.ToLowerInvariant()).ToArray();

        foreach (var code in PermissionCodes)
        {
            if (!Regex.IsMatch(code, @"^[a-z0-9]+(\.[a-z0-9]+)+$"))
                throw new InvalidPermissionCodeException(
                    $"Permission code '{code}' must follow 'module.action' format (lowercase, dot-separated).");
        }
    }

    public bool IsReusable => false;

    public IFilterMetadata CreateInstance(IServiceProvider serviceProvider)
    {
        var filter = ActivatorUtilities.CreateInstance<RequireAnyPermissionFilter>(serviceProvider);
        filter.SetMetadata(this);
        return filter;
    }

    public class RequireAnyPermissionFilter : IAsyncAuthorizationFilter
    {
        private RequireAnyPermissionAttribute? _metadata;
        private readonly IPermissionService _permissionService;
        private readonly ILogger<RequireAnyPermissionFilter> _logger;

        public RequireAnyPermissionFilter(
            IPermissionService permissionService,
            ILogger<RequireAnyPermissionFilter> logger)
        {
            _permissionService = permissionService;
            _logger = logger;
        }

        public void SetMetadata(RequireAnyPermissionAttribute metadata)
        {
            _metadata = metadata;
        }

        public async Task OnAuthorizationAsync(AuthorizationFilterContext context)
        {
            if (_metadata == null)
            {
                context.Result = new ObjectResult(new { error = "Filter misconfigured: metadata not set." })
                {
                    StatusCode = StatusCodes.Status500InternalServerError
                };
                return;
            }

            var user = context.HttpContext.User;
            if (user?.Identity?.IsAuthenticated != true)
            {
                context.Result = new UnauthorizedResult();
                return;
            }

            var userId = user.GetUserId();

            foreach (var code in _metadata.PermissionCodes)
            {
                if (await _permissionService.UserHasPermissionAsync(userId, code, _metadata.ForceLiveCheck))
                {
                    return; // User has at least one — allow
                }
            }

            // User has none of the required permissions
            _logger.LogWarning(
                "Authorization denied (OR check). UserId={UserId} RequiredAny={Permissions} Path={Path}",
                userId, string.Join(", ", _metadata.PermissionCodes), context.HttpContext.Request.Path);

            context.Result = new ObjectResult(new
            {
                error = "forbidden",
                requiredAny = _metadata.PermissionCodes
            })
            {
                StatusCode = StatusCodes.Status403Forbidden
            };
        }
    }
}
""";
    }

    // ═══════════════════════════════════════════════════════════════
    //  API LAYER — CONTROLLERS
    // ═══════════════════════════════════════════════════════════════

    public static string RolesController(ProjectOptions o)
    {
        var p = P(o);
        return $$"""
using {{p}}.Application.Authorization;
using {{p}}.Application.DTOs.Permission;
using {{p}}.Application.Extensions;
using {{p}}.Api.Filters;
using Microsoft.AspNetCore.Mvc;

namespace {{p}}.Api.Controllers;

[ApiController]
[Route("api/roles")]
[RequirePermission("roles", "manage", DisplayName = "Manage Roles", Risk = Domain.Enums.PermissionRisk.Critical, ForceLiveCheck = true)]
public class RolesController : ControllerBase
{
    private readonly IRoleManagementService _roleService;
    private readonly ILogger<RolesController> _logger;

    public RolesController(IRoleManagementService roleService, ILogger<RolesController> logger)
    {
        _roleService = roleService;
        _logger = logger;
    }

    [HttpGet]
    public async Task<IActionResult> GetAll()
    {
        var roles = await _roleService.GetAllRolesAsync();
        return Ok(roles);
    }

    [HttpGet("{roleId}/users")]
    public async Task<IActionResult> GetUsersInRole(string roleId)
    {
        var users = await _roleService.GetUsersInRoleAsync(roleId);
        return Ok(users);
    }

    [HttpPost]
    public async Task<IActionResult> Create([FromBody] CreateRoleRequest request)
    {
        var actorIp = HttpContext.Connection.RemoteIpAddress?.ToString();
        var role = await _roleService.CreateRoleAsync(
            request.Name, request.Description, User.GetUserId(), actorIp);
        return CreatedAtAction(nameof(GetAll), new { id = role.Id }, role);
    }

    [HttpPut("{roleId}/rename")]
    public async Task<IActionResult> Rename(string roleId, [FromBody] RenameRoleRequest request)
    {
        var actorIp = HttpContext.Connection.RemoteIpAddress?.ToString();
        await _roleService.RenameRoleAsync(roleId, request.NewName, User.GetUserId(), actorIp);
        return NoContent();
    }

    [HttpDelete("{roleId}")]
    public async Task<IActionResult> Delete(string roleId)
    {
        var actorIp = HttpContext.Connection.RemoteIpAddress?.ToString();
        await _roleService.DeleteRoleAsync(roleId, User.GetUserId(), actorIp);
        return NoContent();
    }

    [HttpPost("{roleId}/users")]
    public async Task<IActionResult> AssignUser(string roleId, [FromBody] AssignUserRequest request)
    {
        var actorIp = HttpContext.Connection.RemoteIpAddress?.ToString();
        await _roleService.AssignUserToRoleAsync(request.UserId, roleId, User.GetUserId(), actorIp);
        return NoContent();
    }

    [HttpDelete("{roleId}/users/{userId}")]
    public async Task<IActionResult> RemoveUser(string roleId, string userId)
    {
        var actorIp = HttpContext.Connection.RemoteIpAddress?.ToString();
        await _roleService.RemoveUserFromRoleAsync(userId, roleId, User.GetUserId(), actorIp);
        return NoContent();
    }
}
""";
    }

    public static string RolePermissionsController(ProjectOptions o)
    {
        var p = P(o);
        return $$"""
using {{p}}.Application.Authorization;
using {{p}}.Application.DTOs.Permission;
using {{p}}.Application.Extensions;
using {{p}}.Api.Filters;
using {{p}}.Infrastructure.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace {{p}}.Api.Controllers;

[ApiController]
[Route("api/roles/{roleId}/permissions")]
[RequirePermission("permissions", "manage", DisplayName = "Manage Permissions", Risk = Domain.Enums.PermissionRisk.Critical, ForceLiveCheck = true)]
public class RolePermissionsController : ControllerBase
{
    private readonly IPermissionManagementService _permissionService;
    private readonly ILogger<RolePermissionsController> _logger;

    public RolePermissionsController(
        IPermissionManagementService permissionService,
        ILogger<RolePermissionsController> logger)
    {
        _permissionService = permissionService;
        _logger = logger;
    }

    [HttpGet]
    public async Task<IActionResult> GetRolePermissions(string roleId)
    {
        var permissions = await _permissionService.GetRolePermissionsAsync(roleId);
        return Ok(permissions);
    }

    [HttpPost]
    public async Task<IActionResult> GrantPermission(string roleId, [FromBody] GrantPermissionRequest request)
    {
        var actorIp = HttpContext.Connection.RemoteIpAddress?.ToString();
        await _permissionService.GrantPermissionToRoleAsync(roleId, request.PermissionCode);
        await WriteAuditLogAsync("Granted", "Role", roleId, request.PermissionCode, actorIp);
        return NoContent();
    }

    [HttpDelete("{permissionCode}")]
    public async Task<IActionResult> RevokePermission(string roleId, string permissionCode)
    {
        var actorIp = HttpContext.Connection.RemoteIpAddress?.ToString();
        await _permissionService.RevokePermissionFromRoleAsync(roleId, permissionCode);
        await WriteAuditLogAsync("Revoked", "Role", roleId, permissionCode, actorIp);
        return NoContent();
    }

    private async Task WriteAuditLogAsync(string action, string targetType, string targetId, string permissionCode, string? actorIp)
    {
        if (_permissionService is PermissionManagementService pms)
        {
            await pms.WriteAuditLogAsync(User.GetUserId(), targetType, targetId, permissionCode, action, actorIp);
        }
    }
}
""";
    }

    public static string UserPermissionsController(ProjectOptions o)
    {
        var p = P(o);
        return $$"""
using {{p}}.Application.Authorization;
using {{p}}.Application.DTOs.Permission;
using {{p}}.Application.Extensions;
using {{p}}.Api.Filters;
using {{p}}.Infrastructure.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace {{p}}.Api.Controllers;

[ApiController]
[Route("api/users/{userId}/permissions")]
[RequirePermission("permissions", "manage", DisplayName = "Manage Permissions", Risk = Domain.Enums.PermissionRisk.Critical, ForceLiveCheck = true)]
public class UserPermissionsController : ControllerBase
{
    private readonly IPermissionManagementService _permissionService;
    private readonly ILogger<UserPermissionsController> _logger;

    public UserPermissionsController(
        IPermissionManagementService permissionService,
        ILogger<UserPermissionsController> logger)
    {
        _permissionService = permissionService;
        _logger = logger;
    }

    [HttpGet("effective")]
    public async Task<IActionResult> GetEffectivePermissions(string userId)
    {
        var permissions = await _permissionService.GetEffectivePermissionsAsync(userId);
        return Ok(permissions);
    }

    [HttpPost("overrides")]
    public async Task<IActionResult> SetOverride(string userId, [FromBody] SetUserPermissionRequest request)
    {
        var actorIp = HttpContext.Connection.RemoteIpAddress?.ToString();
        await _permissionService.SetUserPermissionOverrideAsync(userId, request.PermissionCode, request.IsGranted);
        var action = request.IsGranted ? "Granted" : "Denied";
        await WriteAuditLogAsync(action, "User", userId, request.PermissionCode, actorIp);
        return NoContent();
    }

    [HttpDelete("overrides/{permissionCode}")]
    public async Task<IActionResult> RemoveOverride(string userId, string permissionCode)
    {
        var actorIp = HttpContext.Connection.RemoteIpAddress?.ToString();
        await _permissionService.RemoveUserPermissionOverrideAsync(userId, permissionCode);
        await WriteAuditLogAsync("OverrideRemoved", "User", userId, permissionCode, actorIp);
        return NoContent();
    }

    private async Task WriteAuditLogAsync(string action, string targetType, string targetId, string permissionCode, string? actorIp)
    {
        if (_permissionService is PermissionManagementService pms)
        {
            await pms.WriteAuditLogAsync(User.GetUserId(), targetType, targetId, permissionCode, action, actorIp);
        }
    }
}
""";
    }

    // ═══════════════════════════════════════════════════════════════
    //  API LAYER — PERMISSIONS MANAGEMENT ENDPOINTS
    // ═══════════════════════════════════════════════════════════════

    public static string PermissionsController(ProjectOptions o)
    {
        var p = P(o);
        return $$"""
using {{p}}.Application.Authorization;
using {{p}}.Application.DTOs.Permission;
using {{p}}.Api.Filters;
using Microsoft.AspNetCore.Mvc;

namespace {{p}}.Api.Controllers;

[ApiController]
[Route("api/permissions")]
[RequirePermission("permissions", "manage", DisplayName = "Manage Permissions", Risk = Domain.Enums.PermissionRisk.Critical, ForceLiveCheck = true)]
public class PermissionsController : ControllerBase
{
    private readonly IPermissionManagementService _permissionService;
    private readonly ILogger<PermissionsController> _logger;

    public PermissionsController(
        IPermissionManagementService permissionService,
        ILogger<PermissionsController> logger)
    {
        _permissionService = permissionService;
        _logger = logger;
    }

    [HttpGet]
    public async Task<IActionResult> GetAll()
    {
        var permissions = await _permissionService.GetAllPermissionsAsync();
        return Ok(permissions);
    }

    [HttpGet("{code}")]
    public async Task<IActionResult> GetByCode(string code)
    {
        var permission = await _permissionService.GetPermissionByCodeAsync(code);
        if (permission == null)
            return NotFound();
        return Ok(permission);
    }

    [HttpGet("changelog")]
    public async Task<IActionResult> GetChangeLog()
    {
        var logs = await _permissionService.GetChangeLogAsync();
        return Ok(logs);
    }

    [HttpPost("prune")]
    public async Task<IActionResult> PruneOrphaned()
    {
        await _permissionService.PruneOrphanedPermissionsAsync();
        return Ok(new { message = "Orphaned permissions pruned." });
    }
}
""";
    }

    // ═══════════════════════════════════════════════════════════════
    //  INFRASTRUCTURE LAYER — APPEND-ONLY MIGRATION HELPER
    // ═══════════════════════════════════════════════════════════════

    public static string PermissionMigrationHelperClass(ProjectOptions o)
    {
        var p = P(o);
        // Use $$"""" (4-quote) delimiter to allow $""" (3-quote) inside the generated code
        return $$"""""
using Microsoft.EntityFrameworkCore.Migrations;

#nullable enable

namespace {{p}}.Infrastructure.Persistence.Migrations;

/// <summary>
/// CRITICAL SECURITY FIX (audit tampering):
///
/// This migration helper applies database-level privileges to enforce
/// append-only semantics on PermissionAuditLog and RoleAuditLog tables.
///
/// After running 'dotnet ef migrations add AddPermissionSystem', you must
/// also apply the following SQL to REVOKE UPDATE and DELETE privileges for
/// the application's runtime database user:
///
/// -- SQL Server
/// REVOKE UPDATE, DELETE ON [dbo].[PermissionAuditLog] TO [your_app_user];
/// REVOKE UPDATE, DELETE ON [dbo].[RoleAuditLog] TO [your_app_user];
/// GRANT INSERT, SELECT ON [dbo].[PermissionAuditLog] TO [your_app_user];
/// GRANT INSERT, SELECT ON [dbo].[RoleAuditLog] TO [your_app_user];
///
/// -- PostgreSQL
/// REVOKE UPDATE, DELETE ON PermissionAuditLog FROM your_app_user;
/// REVOKE UPDATE, DELETE ON RoleAuditLog FROM your_app_user;
///
/// -- SQLite (limited support — use application-level enforcement via SaveChanges interceptor)
/// -- No REVOKE support in SQLite; rely on the interceptor pattern below.
///
/// WARNING: Any EF SaveChangesAsync call that tries to modify or delete an
/// audit row will fail at the database level after these REVOKE statements
/// are applied. This is INTENTIONAL and must NEVER be "fixed" by loosening
/// the grant. If your CI/CD pipeline reports a failure here, it means a
/// code path is attempting to tamper with audit data — investigate the code
/// path, do not loosen the permission.
///
/// For databases that do not support REVOKE (e.g., SQLite), an
/// ISaveChangesInterceptor is also generated to reject UPDATE/DELETE
/// operations on audit entities at the application level.
/// </summary>
public static class AuditTableMigrationHelper
{
    public static string GetRevokeSqlScript(string appUser)
    {
        return $"""
-- CRITICAL SECURITY FIX: Make PermissionAuditLog and RoleAuditLog append-only.
-- These statements REVOKE UPDATE and DELETE privileges for the application user.
-- Only INSERT and SELECT are permitted.
REVOKE UPDATE, DELETE ON [dbo].[PermissionAuditLog] FROM [{appUser}];
REVOKE UPDATE, DELETE ON [dbo].[RoleAuditLog] FROM [{appUser}];
GRANT INSERT, SELECT ON [dbo].[PermissionAuditLog] TO [{appUser}];
GRANT INSERT, SELECT ON [dbo].[RoleAuditLog] TO [{appUser}];
""";
    }

    public static void ApplyAppendOnlyGrants(MigrationBuilder migrationBuilder, string appUser)
    {
        migrationBuilder.Sql(GetRevokeSqlScript(appUser));
    }
}
""""";
    }

    // ═══════════════════════════════════════════════════════════════
    //  INFRASTRUCTURE LAYER — AUDIT TABLE SAVE CHANGES INTERCEPTOR
    // ═══════════════════════════════════════════════════════════════

    public static string AuditSaveChangesInterceptorClass(ProjectOptions o)
    {
        var p = P(o);
        return $$"""
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;

namespace {{p}}.Infrastructure.Persistence;

/// <summary>
/// CRITICAL SECURITY FIX (audit tampering): Application-level enforcement of
/// append-only semantics for audit tables. This interceptor rejects any
/// UPDATE or DELETE operations on PermissionAuditLog and RoleAuditLog entities
/// before they reach the database.
///
/// This is the SECOND line of defense. The FIRST is DB-level REVOKE (see
/// PermissionMigrationHelper). For databases that support REVOKE (SQL Server,
/// PostgreSQL), this interceptor provides defense-in-depth. For databases
/// that don't support REVOKE (SQLite), this is the primary mechanism.
/// </summary>
public class AuditSaveChangesInterceptor : ISaveChangesInterceptor
{
    private static readonly HashSet<string> AuditEntityTypes = new(StringComparer.OrdinalIgnoreCase)
    {
        "PermissionAuditLog",
        "RoleAuditLog"
    };

    public InterceptionResult<int> SavingChanges(DbContextEventData eventData, InterceptionResult<int> result)
    {
        var context = eventData.Context;
        if (context == null) return result;

        DetectAuditTampering(context);
        return result;
    }

    public async ValueTask<InterceptionResult<int>> SavingChangesAsync(
        DbContextEventData eventData,
        InterceptionResult<int> result,
        CancellationToken cancellationToken = default)
    {
        var context = eventData.Context;
        if (context == null) return result;

        DetectAuditTampering(context);
        return result;
    }

    private static void DetectAuditTampering(DbContext context)
    {
        var entries = context.ChangeTracker.Entries()
            .Where(e => AuditEntityTypes.Contains(e.Entity.GetType().Name) &&
                        (e.State == EntityState.Modified || e.State == EntityState.Deleted));

        var tamperEntry = entries.FirstOrDefault();
        if (tamperEntry != null)
        {
            throw new InvalidOperationException(
                $"CRITICAL SECURITY VIOLATION: Attempted to {tamperEntry.State} a row in the " +
                $"{tamperEntry.Entity.GetType().Name} table. This table is append-only by design. " +
                "UPDATE and DELETE are intentionally blocked. Investigate the code path that " +
                "triggered this operation — do not remove this guard.");
        }
    }
}
""";
    }
}
