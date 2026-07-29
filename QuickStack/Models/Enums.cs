namespace QuickStack.Models;

/// <summary>Supported relational database providers.</summary>
public enum DatabaseType
{
    /// <summary>Microsoft SQL Server (localdb or remote).</summary>
    SqlServer,

    /// <summary>PostgreSQL via Npgsql.</summary>
    PostgreSql,

    /// <summary>SQLite file-based database.</summary>
    Sqlite,

    /// <summary>No database (generates no connection string or EF Core packages).</summary>
    None,

    /// <summary>MySQL via Pomelo provider.</summary>
    MySQL
}

/// <summary>Optional features that modify the generated project.</summary>
public enum FeatureType
{
    /// <summary>Swagger with JWT Bearer token input.</summary>
    JwtAuthentication,

    /// <summary>Structured logging via Serilog.</summary>
    SerilogLogging,

    /// <summary>Global exception handling middleware.</summary>
    GlobalExceptionHandling,

    /// <summary>Multi-stage Dockerfile and docker-compose.yml.</summary>
    DockerSupport,

    /// <summary>Rate-limiting middleware for API endpoints.</summary>
    RateLimiting
}

/// <summary>Authentication implementation strategy.</summary>
public enum AuthType
{
    /// <summary>ASP.NET Core Identity with Entity Framework stores + JWT bearer tokens.</summary>
    IdentityWithJwt,

    /// <summary>Lightweight custom JWT with BCrypt password hashing (no Identity dependency).</summary>
    CustomJwt,

    /// <summary>No authentication generated.</summary>
    None
}

/// <summary>How users identify themselves during login.</summary>
public enum LoginIdentifier
{
    /// <summary>Email address only.</summary>
    Email,

    /// <summary>Phone number only.</summary>
    PhoneNumber,

    /// <summary>Email or phone number (auto-detected).</summary>
    Both,

    /// <summary>Username only.</summary>
    Username
}

/// <summary>Email-sending provider for account verification.</summary>
public enum EmailProvider
{
    /// <summary>Resend API (https://resend.com).</summary>
    Resend,

    /// <summary>Google Gmail SMTP.</summary>
    GoogleGmail
}

/// <summary>Flags for optional authentication sub-features.</summary>
[Flags]
public enum AuthFeatures
{
    /// <summary>No additional features.</summary>
    None = 0,

    /// <summary>Enable refresh token rotation with family-wide revocation on reuse.</summary>
    RefreshTokens = 1,

    /// <summary>Email-based account verification during registration.</summary>
    AccountVerification = 2,

    /// <summary>Two-factor authentication support.</summary>
    TwoFactorAuth = 4
}
