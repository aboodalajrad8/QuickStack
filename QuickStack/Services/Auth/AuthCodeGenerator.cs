using System.Text.Json;
using QuickStack.Models;
using QuickStack.Services.Auth.Models;
using QuickStack.Services.Auth.Templates;

namespace QuickStack.Services.Auth;

/// <summary>Generates all auth-related source files for the scaffolded project.</summary>
public class AuthCodeGenerator
{
    private readonly ProjectOptions _options;
    private readonly string _projectDirectory;

    /// <summary>Initializes the generator with project options and output path.</summary>
    /// <param name="options">Project configuration.</param>
    /// <param name="projectDirectory">Root directory of the generated project.</param>
    public AuthCodeGenerator(ProjectOptions options, string projectDirectory)
    {
        _options = options;
        _projectDirectory = projectDirectory;
    }

    /// <summary>Reads the generated project's launchSettings.json to determine the base URL for .http files.</summary>
    private string ResolveBaseUrl()
    {
        var launchPath = Path.Combine(_projectDirectory, "src/Api/Properties/launchSettings.json");
        if (!File.Exists(launchPath))
            return "https://localhost:5001";

        try
        {
            using var doc = JsonDocument.Parse(File.ReadAllText(launchPath));
            var httpsProfile = doc.RootElement
                .GetProperty("profiles")
                .EnumerateObject()
                .FirstOrDefault(p =>
                    p.Value.TryGetProperty("applicationUrl", out var url) &&
                    url.GetString()?.Contains("https://") == true);

            if (httpsProfile.Value.ValueKind == System.Text.Json.JsonValueKind.Undefined)
            {
                httpsProfile = doc.RootElement
                    .GetProperty("profiles")
                    .EnumerateObject()
                    .FirstOrDefault(p =>
                        p.Value.TryGetProperty("applicationUrl", out _));
            }

            var appUrl = httpsProfile.Value.GetProperty("applicationUrl").GetString();
            if (appUrl == null) return "https://localhost:5001";

            var httpsUrl = appUrl.Split(';')
                .FirstOrDefault(u => u.StartsWith("https://", StringComparison.OrdinalIgnoreCase));
            return httpsUrl ?? appUrl.Split(';')[0];
        }
        catch
        {
            return "https://localhost:5001";
        }
    }

    /// <summary>Generates the complete list of source files for the scaffolded project.</summary>
    /// <returns>A list of <see cref="GeneratedFile"/> records with relative paths and content.</returns>
    public List<GeneratedFile> Generate()
    {
        var files = new List<GeneratedFile>();

        if (_options.AuthType != AuthType.None)
        {
            files.AddRange(GeneratePermissionSystem());
        }

        if (_options.AuthType != AuthType.None)
        {
            files.Add(new GeneratedFile(
                "src/Application/DTOs/Auth/RegisterRequest.cs",
                DtoTemplates.RegisterRequest(_options)));

            files.Add(new GeneratedFile(
                "src/Application/DTOs/Auth/LoginRequest.cs",
                DtoTemplates.LoginRequest(_options)));

            files.Add(new GeneratedFile(
                "src/Application/DTOs/Auth/RegisterResponse.cs",
                DtoTemplates.RegisterResponse(_options)));

            files.Add(new GeneratedFile(
                "src/Application/DTOs/Auth/LoginResponse.cs",
                DtoTemplates.LoginResponse(_options)));

            files.Add(new GeneratedFile(
                "src/Application/DTOs/Auth/ErrorResponse.cs",
                DtoTemplates.ErrorResponse(_options)));

            files.Add(new GeneratedFile(
                "src/Application/Interfaces/IRefreshTokenService.cs",
                RefreshTokenServiceTemplates.IRefreshTokenService(_options)));

            if (_options.AuthFeatures.Contains(AuthFeatures.RefreshTokens))
            {
                files.Add(new GeneratedFile(
                    "src/Infrastructure/Services/RefreshTokenService.cs",
                    RefreshTokenServiceTemplates.RefreshTokenService(_options)));
            }

            if (_options.AuthFeatures.Contains(AuthFeatures.AccountVerification))
            {
                files.Add(new GeneratedFile(
                    "src/Application/DTOs/Auth/VerifyEmailRequest.cs",
                    ApplicationServiceTemplates.VerifyEmailRequest(_options)));

                files.Add(new GeneratedFile(
                    "src/Application/DTOs/Auth/VerifyEmailRequestValidator.cs",
                    ApplicationServiceTemplates.VerifyEmailRequestValidator(_options)));

                files.Add(new GeneratedFile(
                    "src/Application/DTOs/Auth/ResendConfirmationRequest.cs",
                    DtoTemplates.ResendConfirmationRequest(_options)));
            }

            files.Add(new GeneratedFile(
                "src/Application/Interfaces/ITokenService.cs",
                CustomJwtTemplates.ITokenService(_options)));

            if (_options.AuthFeatures.Contains(AuthFeatures.AccountVerification))
            {
                files.Add(new GeneratedFile(
                    "src/Application/Interfaces/IEmailService.cs",
                    EmailTemplates.IEmailService(_options)));

                files.Add(new GeneratedFile(
                    "src/Infrastructure/Services/EmailSettings.cs",
                    EmailTemplates.EmailSettings(_options)));

                files.Add(new GeneratedFile(
                    "src/Infrastructure/DependencyInjection/EmailServiceExtensions.cs",
                    EmailTemplates.EmailServiceExtensions(_options)));

                if (_options.EmailProvider == EmailProvider.GoogleGmail)
                {
                    files.Add(new GeneratedFile(
                        "src/Infrastructure/Services/GoogleGmailEmailService.cs",
                        EmailTemplates.GoogleGmailService(_options)));
                }
                else
                {
                    files.Add(new GeneratedFile(
                        "src/Infrastructure/Services/ResendEmailService.cs",
                        EmailTemplates.ResendService(_options)));
                }
            }

            if (_options.AuthType == AuthType.IdentityWithJwt)
                files.AddRange(GenerateIdentityWithJwt());
            else if (_options.AuthType == AuthType.CustomJwt)
                files.AddRange(GenerateCustomJwt());

            if (_options.AuthFeatures.Contains(AuthFeatures.RefreshTokens))
            {
                files.Add(new GeneratedFile(
                    "src/Domain/Entities/RefreshToken.cs",
                    RefreshTokenTemplates.RefreshTokenEntity(_options)));
            }
        }

        if (_options.SelectedFeatures.Contains(FeatureType.RateLimiting) || _options.AuthType != AuthType.None)
        {
            files.Add(new GeneratedFile(
                "src/Api/Middlewares/RateLimitingServiceExtensions.cs",
                RateLimitingTemplates.RateLimitingServices(_options)));
        }

        if (_options.SelectedFeatures.Contains(FeatureType.JwtAuthentication))
        {
            files.Add(new GeneratedFile(
                "src/Api/Middlewares/BearerSecuritySchemeTransformer.cs",
                SwaggerTemplates.SwaggerAuthExtension(_options)));
        }

        if (_options.SelectedFeatures.Contains(FeatureType.GlobalExceptionHandling))
        {
            files.Add(new GeneratedFile(
                "src/Api/Middlewares/ExceptionHandlingMiddleware.cs",
                ExceptionHandlingTemplates.ExceptionHandlingMiddleware(_options)));

            files.Add(new GeneratedFile(
                "src/Api/Middlewares/ExceptionHandlingMiddlewareExtensions.cs",
                ExceptionHandlingTemplates.ExceptionMiddlewareExtension(_options)));
        }

        if (_options.SelectedFeatures.Contains(FeatureType.DockerSupport))
        {
            files.Add(new GeneratedFile(
                "Dockerfile",
                DockerTemplates.Dockerfile(_options)));

            files.Add(new GeneratedFile(
                "docker-compose.yml",
                DockerTemplates.DockerCompose(_options)));
        }

        files.Add(new GeneratedFile(
            "src/Api/Program.cs",
            ProgramTemplate.Generate(_options)));

        files.Add(new GeneratedFile(
            "src/Api/appsettings.json",
            AppSettingsTemplate.AppSettings(_options)));

        files.Add(new GeneratedFile(
            "src/Api/appsettings.Development.json",
            AppSettingsTemplate.AppSettingsDevelopment(_options)));

        files.Add(new GeneratedFile(
            $"src/Api/{_options.ProjectName}.Api.http",
            HttpFileTemplate.Generate(_options, ResolveBaseUrl())));

        files.Add(new GeneratedFile("README.md", AppSettingsTemplate.Readme(_options)));

        return files;
    }

    /// <summary>Generates all permission-system source files (domain entities, application interfaces, infrastructure services, API filters and controllers).</summary>
    private List<GeneratedFile> GeneratePermissionSystem()
    {
        var files = new List<GeneratedFile>();

        files.Add(new GeneratedFile(
            "src/Domain/Enums/PermissionRisk.cs",
            PermissionTemplates.PermissionRiskEnum(_options)));

        files.Add(new GeneratedFile(
            "src/Domain/Exceptions/InvalidPermissionCodeException.cs",
            PermissionTemplates.InvalidPermissionCodeException(_options)));

        files.Add(new GeneratedFile(
            "src/Domain/Exceptions/ForbiddenException.cs",
            PermissionTemplates.ForbiddenException(_options)));

        files.Add(new GeneratedFile(
            "src/Domain/Exceptions/NotFoundException.cs",
            PermissionTemplates.NotFoundException(_options)));

        files.Add(new GeneratedFile(
            "src/Domain/Exceptions/PermissionNotFoundException.cs",
            PermissionTemplates.PermissionNotFoundException(_options)));

        files.Add(new GeneratedFile(
            "src/Domain/Entities/IOwnedEntity.cs",
            PermissionTemplates.IOwnedEntityInterface(_options)));

        files.Add(new GeneratedFile(
            "src/Domain/Entities/Permission.cs",
            PermissionTemplates.PermissionEntity(_options)));

        files.Add(new GeneratedFile(
            "src/Domain/Entities/RolePermission.cs",
            PermissionTemplates.RolePermissionEntity(_options)));

        files.Add(new GeneratedFile(
            "src/Domain/Entities/UserPermission.cs",
            PermissionTemplates.UserPermissionEntity(_options)));

        files.Add(new GeneratedFile(
            "src/Domain/Entities/PermissionChangeLog.cs",
            PermissionTemplates.PermissionChangeLogEntity(_options)));

        files.Add(new GeneratedFile(
            "src/Domain/Entities/PermissionAuditLog.cs",
            PermissionTemplates.PermissionAuditLogEntity(_options)));

        files.Add(new GeneratedFile(
            "src/Domain/Entities/RoleAuditLog.cs",
            PermissionTemplates.RoleAuditLogEntity(_options)));

        files.Add(new GeneratedFile(
            "src/Application/DTOs/Permission/PermissionDto.cs",
            PermissionTemplates.PermissionDto(_options)));

        files.Add(new GeneratedFile(
            "src/Application/DTOs/Permission/RoleDto.cs",
            PermissionTemplates.RoleDto(_options)));

        files.Add(new GeneratedFile(
            "src/Application/Extensions/ClaimsPrincipalExtensions.cs",
            PermissionTemplates.ClaimsPrincipalExtensions(_options)));

        files.Add(new GeneratedFile(
            "src/Application/Authorization/IPermissionService.cs",
            PermissionTemplates.IPermissionServiceInterface(_options)));

        files.Add(new GeneratedFile(
            "src/Application/Authorization/IPermissionCache.cs",
            PermissionTemplates.IPermissionCacheInterface(_options)));

        files.Add(new GeneratedFile(
            "src/Application/Authorization/IResourceAuthorizationService.cs",
            PermissionTemplates.IResourceAuthorizationServiceInterface(_options)));

        files.Add(new GeneratedFile(
            "src/Application/Authorization/IPermissionManagementService.cs",
            PermissionTemplates.IPermissionManagementServiceInterface(_options)));

        files.Add(new GeneratedFile(
            "src/Application/Authorization/IRoleManagementService.cs",
            PermissionTemplates.IRoleManagementServiceInterface(_options)));

        files.Add(new GeneratedFile(
            "src/Api/Filters/RequirePermissionAttribute.cs",
            PermissionTemplates.RequirePermissionAttributeClass(_options)));

        files.Add(new GeneratedFile(
            "src/Api/Filters/RequirePermissionFilter.cs",
            PermissionTemplates.RequirePermissionFilterClass(_options)));

        files.Add(new GeneratedFile(
            "src/Api/Filters/RequireAnyPermissionAttribute.cs",
            PermissionTemplates.RequireAnyPermissionAttributeClass(_options)));

        files.Add(new GeneratedFile(
            "src/Infrastructure/Authorization/PermissionCache.cs",
            PermissionTemplates.PermissionCacheClass(_options)));

        files.Add(new GeneratedFile(
            "src/Infrastructure/Authorization/PermissionService.cs",
            PermissionTemplates.PermissionServiceClass(_options)));

        files.Add(new GeneratedFile(
            "src/Infrastructure/Authorization/DefaultOwnershipResourceAuthorizationService.cs",
            PermissionTemplates.DefaultOwnershipResourceAuthorizationServiceClass(_options)));

        files.Add(new GeneratedFile(
            "src/Infrastructure/Authorization/PermissionDiscoveryService.cs",
            PermissionTemplates.PermissionDiscoveryServiceClass(_options)));

        files.Add(new GeneratedFile(
            "src/Infrastructure/Authorization/PermissionSyncService.cs",
            PermissionTemplates.PermissionSyncServiceClass(_options)));

        files.Add(new GeneratedFile(
            "src/Infrastructure/Authorization/PermissionManagementService.cs",
            PermissionTemplates.PermissionManagementServiceClass(_options)));

        if (_options.AuthType == AuthType.IdentityWithJwt)
        {
            files.Add(new GeneratedFile(
                "src/Infrastructure/Authorization/RoleManagementService.cs",
                PermissionTemplates.RoleManagementServiceClass(_options)));

            files.Add(new GeneratedFile(
                "src/Infrastructure/Authorization/PermissionSeedService.cs",
                PermissionTemplates.PermissionSeedServiceClass(_options)));
        }

        files.Add(new GeneratedFile(
            "src/Infrastructure/DependencyInjection/PermissionServiceExtensions.cs",
            PermissionTemplates.PermissionServiceExtensionsClass(_options)));

        files.Add(new GeneratedFile(
            "src/Infrastructure/Persistence/Migrations/AuditTableMigrationHelper.cs",
            PermissionTemplates.PermissionMigrationHelperClass(_options)));

        files.Add(new GeneratedFile(
            "src/Infrastructure/Persistence/AuditSaveChangesInterceptor.cs",
            PermissionTemplates.AuditSaveChangesInterceptorClass(_options)));

        if (_options.AuthType == AuthType.IdentityWithJwt)
        {
            files.Add(new GeneratedFile(
                "src/Api/Controllers/RolesController.cs",
                PermissionTemplates.RolesController(_options)));
        }

        files.Add(new GeneratedFile(
            "src/Api/Controllers/RolePermissionsController.cs",
            PermissionTemplates.RolePermissionsController(_options)));

        files.Add(new GeneratedFile(
            "src/Api/Controllers/UserPermissionsController.cs",
            PermissionTemplates.UserPermissionsController(_options)));

        files.Add(new GeneratedFile(
            "src/Api/Controllers/PermissionsController.cs",
            PermissionTemplates.PermissionsController(_options)));

        return files;
    }

    /// <summary>Generates files specific to ASP.NET Core Identity + JWT auth mode.</summary>
    private List<GeneratedFile> GenerateIdentityWithJwt()
    {
        var files = new List<GeneratedFile>
        {
            new GeneratedFile(
                "src/Infrastructure/Persistence/AppUser.cs",
                IdentityTemplates.AppUser(_options)),

            new GeneratedFile(
                "src/Infrastructure/Persistence/AppDbContext.cs",
                IdentityTemplates.IdentityDbContext(_options)),

            new GeneratedFile(
                "src/Infrastructure/Services/JwtSettings.cs",
                CustomJwtTemplates.JwtSettings(_options)),

            new GeneratedFile(
                "src/Infrastructure/Services/JwtTokenGenerator.cs",
                IdentityTemplates.JwtTokenGenerator(_options)),

            new GeneratedFile(
                "src/Infrastructure/Persistence/ApplicationRole.cs",
                PermissionTemplates.ApplicationRoleEntity(_options)),

            new GeneratedFile(
                "src/Infrastructure/DependencyInjection/IdentityServiceExtensions.cs",
                ServiceCollectionTemplates.IdentityServiceCollectionExtensions(_options)),

            new GeneratedFile(
                "src/Api/Controllers/AuthController.cs",
                ControllerTemplates.AuthController(_options)),
        };

        return files;
    }

    /// <summary>Generates files specific to Custom JWT auth mode.</summary>
    private List<GeneratedFile> GenerateCustomJwt()
    {
        var files = new List<GeneratedFile>
        {
            new GeneratedFile(
                "src/Domain/Entities/User.cs",
                CustomJwtTemplates.UserEntity(_options)),

            new GeneratedFile(
                "src/Infrastructure/Services/JwtSettings.cs",
                CustomJwtTemplates.JwtSettings(_options)),

            new GeneratedFile(
                "src/Infrastructure/Services/TokenService.cs",
                CustomJwtTemplates.TokenService(_options)),

            new GeneratedFile(
                "src/Infrastructure/Persistence/AppDbContext.cs",
                ServiceCollectionTemplates.CustomJwtDbContext(_options)),

            new GeneratedFile(
                "src/Infrastructure/DependencyInjection/CustomJwtServiceExtensions.cs",
                ServiceCollectionTemplates.CustomJwtServiceCollectionExtensions(_options)),

            new GeneratedFile(
                "src/Api/Controllers/AuthController.cs",
                ControllerTemplates.CustomJwtAuthController(_options)),
        };

        return files;
    }
}
