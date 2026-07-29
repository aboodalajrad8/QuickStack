using QuickStack.Models;

namespace QuickStack.Services.Auth.Templates;

public static class AppSettingsTemplate
{
    private static string EmailConfig(ProjectOptions o)
    {
        if (!o.AuthFeatures.Contains(AuthFeatures.AccountVerification))
            return "";

        return $$"""
  "EmailSettings": {
    "Provider": "{{(o.EmailProvider == EmailProvider.GoogleGmail ? "GoogleGmail" : "Resend")}}",
    {{(o.EmailProvider == EmailProvider.GoogleGmail ? "" : "\"ResendApiKey\": \"\"," )}}
    "SmtpServer": "smtp.gmail.com",
    "SmtpPort": 465,
    "SmtpUsername": "",
    "SmtpPassword": "",
    "SenderEmail": "noreply@{{o.ProjectName.ToLower()}}.com",
    "SenderName": "{{o.ProjectName}}"
  },
""";
    }

    private static string JwtConfig(ProjectOptions o)
    {
        if (o.AuthType == AuthType.None) return "";

        return $$"""
  // ⚠️ DUMMY SECRET — Replace before deployment. See README.md for instructions.
  "JwtSettings": {
    "SecretKey": "SuperSecretKey_{{o.ProjectName}}_ChangeMeInProduction_Min32Chars!!",
    "Issuer": "{{o.ProjectName}}",
    "Audience": "{{o.ProjectName}}",
    "ExpiryInMinutes": 15
  },
""";
    }

    private static string JwtConfigDev(ProjectOptions o)
    {
        if (o.AuthType == AuthType.None) return "";

        return $$"""
  // ⚠️ DUMMY SECRET — Override with `dotnet user-secrets set "JwtSettings:SecretKey" "..."`.
  "JwtSettings": {
    "SecretKey": "SuperSecretKey_{{o.ProjectName}}_DevOnly_Min32Chars!!",
    "Issuer": "{{o.ProjectName}}",
    "Audience": "{{o.ProjectName}}",
    "ExpiryInMinutes": 15
  },
""";
    }

    private static string RefreshTokenConfig(ProjectOptions o)
    {
        if (!o.AuthFeatures.Contains(AuthFeatures.RefreshTokens)) return "";

        return $$"""
  // Refresh token lifetime. Access tokens are short-lived (15 min default),
  // refresh tokens can live longer (7–30 days recommended).
  "RefreshTokenSettings": {
    "RefreshTokenExpirationDays": 7
  },
""";
    }

    private static string CorsConfig(ProjectOptions o)
    {
        return $$"""
  // ⚠️ Configure allowed CORS origins for your front-end.
  "CorsSettings": {
    "AllowedOrigins": [
      "https://localhost:3000",
      "https://yourdomain.com"
    ]
  },
""";
    }

    private static string PermissionsConfig(ProjectOptions o)
    {
        if (o.AuthType == AuthType.None) return "";

        return $$"""
  // Permission system configuration
  // CRITICAL SECURITY: AutoSync should be false in production. Use explicit
  // 'quickstack permissions sync' during deployment. SeedOnFirstRun creates
  // the SuperAdmin role with all discovered permissions.
  "Permissions": {
    "AutoSync": false,
    "SeedOnFirstRun": true,
    "ScanAssemblies": ["{{o.ProjectName}}.Api"],
    "AlwaysLiveCheck": [
      "permissions.manage",
      "roles.manage",
      "users.delete",
      "users.manage"
    ]
  },
""";
    }

    private static string RateLimitingConfig(ProjectOptions o)
    {
        return $$"""
  // Rate limiting protects auth endpoints from brute-force and credential-stuffing attacks.
  // Adjust limits based on your expected traffic patterns.
  "RateLimiting": {
    "AuthPolicy": {
      "PermitLimit": 10,
      "WindowInMinutes": 1
    },
    "LoginPolicy": {
      "PermitLimit": 5,
      "WindowInMinutes": 1
    },
    "RefreshPolicy": {
      "PermitLimit": 10,
      "WindowInMinutes": 1
    },
    "ResendConfirmationPolicy": {
      "PermitLimit": 3,
      "WindowInMinutes": 5
    }
  },
""";
    }

    private static string ConnectionStringConfig(ProjectOptions o)
    {
        if (o.Database == DatabaseType.None) return "";

        var connStr = o.Database switch
        {
            DatabaseType.SqlServer => $"Server=(localdb)\\\\mssqllocaldb;Database={o.ProjectName}Db;Trusted_Connection=True;MultipleActiveResultSets=true",
            DatabaseType.PostgreSql => $"Host=localhost;Port=5432;Database={o.ProjectName}Db;Username=postgres;Password=postgres",
            DatabaseType.MySQL => $"Server=localhost;Port=3306;Database={o.ProjectName}Db;User=root;Password=root",
            DatabaseType.Sqlite => $"Data Source={o.ProjectName}.db",
            _ => $"Server=(localdb)\\\\mssqllocaldb;Database={o.ProjectName}Db;Trusted_Connection=True;MultipleActiveResultSets=true"
        };

        return $$"""
  "ConnectionStrings": {
    "DefaultConnection": "{{connStr}}"
  },
""";
    }

    public static string AppSettings(ProjectOptions o)
    {
        var email = EmailConfig(o);
        var jwt = JwtConfig(o);
        var refresh = RefreshTokenConfig(o);
        var cors = CorsConfig(o);
        var rateLimit = RateLimitingConfig(o);
        var permissions = PermissionsConfig(o);
        var connStr = ConnectionStringConfig(o);
        return $$"""
{
  "Logging": {
    "LogLevel": {
      "Default": "Information",
      "Microsoft.AspNetCore": "Warning"
    }
  },
{{connStr}}{{jwt}}{{refresh}}{{permissions}}{{email}}{{cors}}{{rateLimit}}  "AllowedHosts": "*"
}
""";
    }

    public static string Readme(ProjectOptions o)
    {
        var p = o.ProjectName;
        return $$"""
# {{p}}

## Security Instructions

### JWT Secret Key

**⚠️ IMPORTANT:** The JWT `SecretKey` in `appsettings.json` is a dummy placeholder.

- **For Development:** Use `dotnet user-secrets` to store the secret:
  ```
  dotnet user-secrets set "JwtSettings:SecretKey" "<your-secret-key-min-32-chars>"
  ```
- **For Production:** Use Environment Variables or Azure Key Vault:
  ```
  # Environment variable (Linux/macOS)
  export JwtSettings__SecretKey="<your-secret-key-min-32-chars>"

  # Environment variable (Windows)
  setx JwtSettings__SecretKey "<your-secret-key-min-32-chars>"
  ```
  Or configure Azure Key Vault in `Program.cs`.

The secret key must be at least 32 characters long.

### Refresh Token Security

- Refresh tokens are stored as SHA-256 hashes in the database — the raw token is never persisted.
- Delivered via HttpOnly, Secure, SameSite=Strict cookies (never in localStorage).
- Rotated on every use. Reuse of a rotated token triggers family-wide revocation.
- Access tokens are short-lived (default: 15 minutes). Refresh tokens live 7 days.

### Email Settings

Email credentials are set in `appsettings.json` under `EmailSettings`. For development, override these using `dotnet user-secrets`:
```
dotnet user-secrets set "EmailSettings:ResendApiKey" "<your-api-key>"
dotnet user-secrets set "EmailSettings:SmtpUsername" "<your-email>"
dotnet user-secrets set "EmailSettings:SmtpPassword" "<your-password>"
```

### CORS

CORS origins are configured in the `CorsSettings:AllowedOrigins` section of `appsettings.json`.
Override for your environment:
```json
{
  "CorsSettings": {
    "AllowedOrigins": ["https://your-frontend-domain.com"]
  }
}
```

### Rate Limiting

Auth endpoints are rate-limited to mitigate brute-force and credential-stuffing attacks.
Configure limits in `appsettings.json` under `RateLimiting`:
- **Auth (general):** 10 requests per minute
- **Login:** 5 requests per minute
- **Refresh:** 10 requests per minute
- **Resend Confirmation:** 3 requests per 5 minutes

### Connection Strings

For production, never hardcode connection strings in `appsettings.json`. Use:
```
dotnet user-secrets set "ConnectionStrings:DefaultConnection" "<your-connection-string>"
```
Or Environment Variables / Azure Key Vault.
""";
    }

    public static string AppSettingsDevelopment(ProjectOptions o)
    {
        var email = EmailConfig(o);
        var jwt = JwtConfigDev(o);
        var refresh = RefreshTokenConfig(o);
        var cors = CorsConfig(o);
        var rateLimit = RateLimitingConfig(o);
        var permissions = PermissionsConfig(o);
        var connStr = ConnectionStringConfig(o);
        return $$"""
{
  "Logging": {
    "LogLevel": {
      "Default": "Information",
      "Microsoft.AspNetCore": "Warning"
    }
  },
{{connStr}}{{jwt}}{{refresh}}{{permissions}}{{email}}{{cors}}{{rateLimit}}  "AllowedHosts": "*"
}
""";
    }
}
