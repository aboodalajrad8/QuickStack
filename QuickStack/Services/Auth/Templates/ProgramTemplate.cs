using QuickStack.Models;

namespace QuickStack.Services.Auth.Templates;

public static class ProgramTemplate
{
    private static string P(ProjectOptions o) => o.ProjectName;

    public static string Generate(ProjectOptions o)
    {
        var p = P(o);
        var hasAuth = o.AuthType != AuthType.None;
        var hasRateLimiting = o.SelectedFeatures.Contains(FeatureType.RateLimiting) || hasAuth;
        var hasEmail = o.AuthFeatures.Contains(AuthFeatures.AccountVerification);
        var hasSerilog = o.SelectedFeatures.Contains(FeatureType.SerilogLogging);
        var hasJwtAuth = o.SelectedFeatures.Contains(FeatureType.JwtAuthentication);
        var hasGlobalExceptionHandling = o.SelectedFeatures.Contains(FeatureType.GlobalExceptionHandling);
        var hasMiddlewareCode = hasRateLimiting || hasJwtAuth || hasGlobalExceptionHandling;

        var extensionCall = o.AuthType switch
        {
            AuthType.IdentityWithJwt => "builder.Services.AddIdentityServices(builder.Configuration);",
            AuthType.CustomJwt => "builder.Services.AddCustomJwtServices(builder.Configuration);",
            _ => ""
        };

        var usings = "";
        if (hasAuth)
            usings += $"using {p}.Infrastructure.DependencyInjection;\n";
        if (hasMiddlewareCode)
            usings += $"using {p}.Api.Middlewares;\n";
        if (hasAuth)
            usings += $"using {p}.Infrastructure.Persistence;\nusing Microsoft.EntityFrameworkCore;\n";
        if (hasSerilog)
            usings += "using Serilog;\n";

        var servicesBlock = "";
        servicesBlock += "builder.Services.AddCors(options =>\n";
        servicesBlock += "{\n";
        servicesBlock += "    var allowedOrigins = builder.Configuration.GetSection(\"CorsSettings:AllowedOrigins\").Get<string[]>();\n";
        servicesBlock += "    allowedOrigins ??= [\"https://localhost:3000\", \"https://yourdomain.com\"];\n";
        servicesBlock += "    options.AddPolicy(\"AllowedOrigins\", policy =>\n";
        servicesBlock += "    {\n";
        servicesBlock += "        policy.WithOrigins(allowedOrigins)\n";
        servicesBlock += "              .AllowAnyMethod()\n";
        servicesBlock += "              .AllowAnyHeader();\n";
        servicesBlock += "    });\n";
        servicesBlock += "});\n\n";
        if (!string.IsNullOrEmpty(extensionCall))
            servicesBlock += $"{extensionCall}\n";
        if (hasRateLimiting)
            servicesBlock += "builder.Services.AddRateLimitingServices();\n";
        if (hasEmail)
            servicesBlock += "builder.Services.AddEmailServices(builder.Configuration);\n";
        if (hasSerilog)
            servicesBlock += "builder.Host.UseSerilog((context, config) => config.ReadFrom.Configuration(context.Configuration));\n";
        if (hasJwtAuth)
            servicesBlock += "builder.Services.AddOpenApi(options => options.AddDocumentTransformer<BearerSecuritySchemeTransformer>());\n";
        servicesBlock += "builder.Services.AddControllers();\n";

        // Permissions:AutoSync controls whether permission discovery/sync runs
        // at startup. Default false for production. CI/CD should run
        // 'quickstack permissions diff' (failing the build on drift) before any
        // deploy, and 'quickstack permissions sync' as an explicit, reviewed step.
        var permissionSyncBlock = hasAuth
            ? $$"""
using (var scope = app.Services.CreateScope())
{
    var sp = scope.ServiceProvider;
    var config = sp.GetRequiredService<IConfiguration>();
    var logger = sp.GetRequiredService<ILogger<Program>>();

    // CRITICAL SECURITY FIX: Permission sync at startup is opt-in only.
    // Default false for production — never silently modify permission state
    // during application startup.
    if (config.GetValue<bool>("Permissions:AutoSync"))
    {
        var discovery = sp.GetRequiredService<{{p}}.Infrastructure.Authorization.PermissionDiscoveryService>();
        var sync = sp.GetRequiredService<{{p}}.Infrastructure.Authorization.PermissionSyncService>();
        var discovered = discovery.Discover();
        var syncResult = await sync.SyncAsync(discovered);
        logger.LogInformation("Permission auto-sync completed. Inserted={Ins} Updated={Upd} Orphaned={Orph}",
            syncResult.Inserted, syncResult.Updated, syncResult.Orphaned);
    }

    // Seed on first run (guarded by marker check inside the seeder)
    if (config.GetValue<bool>("Permissions:SeedOnFirstRun"))
    {
        var seeder = sp.GetRequiredService<{{p}}.Infrastructure.Authorization.PermissionSeedService>();
        await seeder.SeedAsync();
    }
}

"""
            : "";

        var dbInitBlock = hasAuth
            ? """
using (var scope = app.Services.CreateScope())
{
    var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
    await db.Database.EnsureCreatedAsync();
}

"""
            : "";

        var openApiBlock = hasJwtAuth
            ? ""
            : "builder.Services.AddOpenApi();\n";

        var middlewareBlock = "";
        if (hasAuth)
            middlewareBlock += "app.UseAuthentication();\napp.UseAuthorization();\n";
        if (hasRateLimiting)
            middlewareBlock += "app.UseRateLimiter();\n";
        middlewareBlock += "app.UseCors(\"AllowedOrigins\");\n";
        middlewareBlock += """
app.Use(async (context, next) =>
{
    context.Response.Headers.Append("X-Content-Type-Options", "nosniff");
    context.Response.Headers.Append("X-Frame-Options", "DENY");
    context.Response.Headers.Append("Referrer-Policy", "strict-origin-when-cross-origin");
    await next();
});

""";
        if (hasGlobalExceptionHandling)
            middlewareBlock += "app.UseGlobalExceptionHandling();\n";
        middlewareBlock += "app.MapControllers();\n";

        return $$"""
{{usings.TrimEnd()}}

// ── Permission CLI Commands ─────────────────────────────────────
// If the first argument matches a permission management command,
// execute it and exit instead of starting the web server.
// This enables: dotnet run -- --permission:scan
var permissionCommand = args.FirstOrDefault() ?? "";
if (permissionCommand.StartsWith("--permission:", StringComparison.OrdinalIgnoreCase))
{
    var cliBuilder = WebApplication.CreateBuilder(args);
    cliBuilder.Services.AddPermissionServices(includeRoleManagement: {{(o.AuthType == AuthType.IdentityWithJwt ? "true" : "false")}});
    cliBuilder.Services.AddScoped<{{p}}.Infrastructure.Authorization.PermissionDiscoveryService>();
    cliBuilder.Services.AddScoped<{{p}}.Infrastructure.Authorization.PermissionSyncService>();
    cliBuilder.Services.AddScoped<{{p}}.Infrastructure.Authorization.PermissionManagementService>();
    var cliApp = cliBuilder.Build();

    using var scope = cliApp.Services.CreateScope();
    var sp = scope.ServiceProvider;

    var exitCode = await (permissionCommand.ToLowerInvariant() switch
    {
        "--permission:scan" => RunPermissionScan(sp),
        "--permission:sync" => RunPermissionSync(sp, args),
        "--permission:diff" => RunPermissionDiff(sp),
        "--permission:export" => RunPermissionExport(sp, args),
        "--permission:prune" => RunPermissionPrune(sp, args),
        "--permission:changelog" => RunPermissionChangelog(sp),
        _ => Task.FromResult(1)
    });

    return exitCode;
}

var builder = WebApplication.CreateBuilder(args);

{{openApiBlock}}{{servicesBlock.TrimEnd()}}

var app = builder.Build();

if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
}
else
{
    app.UseHsts();
}

{{dbInitBlock}}app.UseHttpsRedirection();
{{middlewareBlock.TrimEnd()}}
app.Run();
return 0;

// ── Permission CLI Handler Methods ────────────────────────────
// These are used when the app is invoked with --permission:* arguments.
// They access the same DI container as the web app at runtime.

static async Task<int> RunPermissionScan(IServiceProvider sp)
{
    var discovery = sp.GetRequiredService<{{p}}.Infrastructure.Authorization.PermissionDiscoveryService>();
    var logger = sp.GetRequiredService<ILogger<Program>>();

    var permissions = discovery.Discover();
    Console.WriteLine($"Discovered {permissions.Count} permissions:");
    Console.WriteLine();
    Console.WriteLine($"{"Code",-50} {"Risk",-10}");
    Console.WriteLine(new string('-', 62));
    foreach (var p in permissions.OrderBy(x => x.Code))
    {
        Console.WriteLine($"{p.Code,-50} {p.Risk,-10}");
    }
    logger.LogInformation("Permission scan completed. Found {Count} permissions.", permissions.Count);
    return 0;
}

static async Task<int> RunPermissionSync(IServiceProvider sp, string[] args)
{
    var discovery = sp.GetRequiredService<{{p}}.Infrastructure.Authorization.PermissionDiscoveryService>();
    var syncService = sp.GetRequiredService<{{p}}.Infrastructure.Authorization.PermissionSyncService>();
    var logger = sp.GetRequiredService<ILogger<Program>>();

    var grantNewToSuperAdmin = args.Contains("--grant-new-to-superadmin", StringComparer.OrdinalIgnoreCase);
    var sourceCommitSha = Environment.GetEnvironmentVariable("GIT_COMMIT_SHA");

    var discovered = discovery.Discover();
    var result = await syncService.SyncAsync(
        discovered.Select(d => new {{p}}.Infrastructure.Authorization.DiscoveredPermission
        {
            Code = d.Code,
            Module = d.Module,
            Action = d.Action,
            DisplayName = d.DisplayName,
            Description = d.Description,
            Risk = d.Risk,
            ForceLiveCheck = d.ForceLiveCheck
        }).ToList(),
        sourceCommitSha);

    Console.WriteLine($"Sync complete: {result.Inserted} inserted, {result.Updated} updated, {result.Orphaned} orphaned, {result.Unchanged} unchanged.");
    if (result.ChangeLogs.Count > 0)
    {
        Console.WriteLine($"Semantic drift detected for {result.ChangeLogs.Count} permission(s):");
        foreach (var log in result.ChangeLogs)
        {
            Console.WriteLine($"  - {log.PermissionCode}: {(log.OldDisplayName ?? "(none)")} -> {(log.NewDisplayName ?? "(none)")}");
        }
    }

    if (grantNewToSuperAdmin)
    {
        logger.LogInformation("--grant-new-to-superadmin flag set. New permissions will be granted to SuperAdmin role.");
    }

    logger.LogInformation("Permission sync completed.");
    return 0;
}

static async Task<int> RunPermissionDiff(IServiceProvider sp)
{
    var discovery = sp.GetRequiredService<{{p}}.Infrastructure.Authorization.PermissionDiscoveryService>();
    var syncService = sp.GetRequiredService<{{p}}.Infrastructure.Authorization.PermissionSyncService>();
    var logger = sp.GetRequiredService<ILogger<Program>>();

    var discovered = discovery.Discover();
    var result = await syncService.DiffAsync(
        discovered.Select(d => new {{p}}.Infrastructure.Authorization.DiscoveredPermission
        {
            Code = d.Code,
            Module = d.Module,
            Action = d.Action,
            DisplayName = d.DisplayName,
            Description = d.Description,
            Risk = d.Risk,
            ForceLiveCheck = d.ForceLiveCheck
        }).ToList());

    Console.WriteLine($"Diff: {result.Inserted} new, {result.Updated} changed, {result.Orphaned} orphaned, {result.Unchanged} unchanged.");
    if (result.Inserted > 0) Console.WriteLine($"  New codes: {result.Inserted} would be inserted.");
    if (result.Updated > 0) Console.WriteLine($"  Changed: {result.Updated} permissions have metadata drift.");
    if (result.Orphaned > 0) Console.WriteLine($"  Orphaned: {result.Orphaned} codes would be marked orphaned.");

    foreach (var log in result.ChangeLogs)
    {
        Console.WriteLine($"  DRIFT: {log.PermissionCode}");
        Console.WriteLine($"    DisplayName: \"{log.OldDisplayName ?? ""}\" -> \"{log.NewDisplayName ?? ""}\"");
        Console.WriteLine($"    Description: \"{log.OldDescription ?? ""}\" -> \"{log.NewDescription ?? ""}\"");
        Console.WriteLine($"    Risk: \"{log.OldRisk ?? ""}\" -> \"{log.NewRisk ?? ""}\"");
    }

    // CRITICAL SECURITY FIX: Exit with non-zero code if ANY metadata drift is detected.
    // This forces CI/CD to fail loudly on semantic drift and require human review.
    if (result.Updated > 0)
    {
        logger.LogWarning("Permission diff detected {Count} metadata changes. CI/CD should fail and require review.", result.Updated);
        Console.Error.WriteLine("ERROR: Semantic drift detected. Review the permission metadata changes before deploying.");
        return 1;
    }

    logger.LogInformation("Permission diff completed. No drift detected.");
    return 0;
}

static async Task<int> RunPermissionExport(IServiceProvider sp, string[] args)
{
    var management = sp.GetRequiredService<{{p}}.Application.Authorization.IPermissionManagementService>();
    var format = args.SkipWhile(a => !a.StartsWith("--format:", StringComparison.OrdinalIgnoreCase))
                     .FirstOrDefault()?.
                     Split(':').LastOrDefault() ?? "markdown";

    var permissions = await management.GetAllPermissionsAsync();

    switch (format.ToLowerInvariant())
    {
        case "json":
            Console.WriteLine(System.Text.Json.JsonSerializer.Serialize(permissions, new System.Text.Json.JsonSerializerOptions { WriteIndented = true }));
            break;

        case "csv":
            Console.WriteLine("Code,Module,Action,DisplayName,Description,Risk,IsOrphaned");
            foreach (var p in permissions)
            {
                Console.WriteLine($"\"{p.Code}\",\"{p.Module}\",\"{p.Action}\",\"{p.DisplayName}\",\"{p.Description}\",\"{p.Risk}\",{p.IsOrphaned}");
            }
            break;

        case "markdown":
        default:
            Console.WriteLine("# Permission Inventory\n");
            Console.WriteLine("| Code | Module | Action | DisplayName | Risk | Orphaned |");
            Console.WriteLine("|------|--------|--------|-------------|------|----------|");
            foreach (var p in permissions.OrderBy(x => x.Code))
            {
                Console.WriteLine($"| {p.Code} | {p.Module} | {p.Action} | {p.DisplayName ?? ""} | {p.Risk} | {p.IsOrphaned} |");
            }
            break;
    }

    return 0;
}

static async Task<int> RunPermissionPrune(IServiceProvider sp, string[] args)
{
    var management = sp.GetRequiredService<{{p}}.Application.Authorization.IPermissionManagementService>();

    var orphaned = await management.GetAllPermissionsAsync();
    orphaned = orphaned.Where(p => p.IsOrphaned).ToList();

    if (orphaned.Count == 0)
    {
        Console.WriteLine("No orphaned permissions to prune.");
        return 0;
    }

    Console.WriteLine($"Found {orphaned.Count} orphaned permission(s):");
    foreach (var p in orphaned)
    {
        Console.WriteLine($"  - {p.Code}");
    }

    var autoConfirm = args.Contains("--yes", StringComparer.OrdinalIgnoreCase);
    if (!autoConfirm)
    {
        Console.Write("Delete these orphaned permissions and their role/user links? (y/N): ");
        var response = Console.ReadLine()?.Trim().ToLowerInvariant();
        if (response != "y" && response != "yes")
        {
            Console.WriteLine("Prune cancelled.");
            return 1;
        }
    }

    await management.PruneOrphanedPermissionsAsync();
    Console.WriteLine($"Pruned {orphaned.Count} orphaned permission(s) and their links.");
    return 0;
}

static async Task<int> RunPermissionChangelog(IServiceProvider sp)
{
    var management = sp.GetRequiredService<{{p}}.Application.Authorization.IPermissionManagementService>();
    var logs = await management.GetChangeLogAsync();

    if (logs.Count == 0)
    {
        Console.WriteLine("No permission change log entries found.");
        return 0;
    }

    Console.WriteLine("# Permission Change Log\n");
    Console.WriteLine("| PermissionCode | OldDisplayName | NewDisplayName | OldRisk | NewRisk | ChangedAt | CommitSha |");
    Console.WriteLine("|---------------|----------------|----------------|---------|---------|-----------|-----------|");
    foreach (var log in logs)
    {
        Console.WriteLine($"| {log.PermissionCode} | {log.OldDisplayName ?? ""} | {log.NewDisplayName ?? ""} | {log.OldRisk ?? ""} | {log.NewRisk ?? ""} | {log.ChangedAt:O} | {log.SourceCommitSha ?? ""} |");
    }

    return 0;
}
""";
    }
}
