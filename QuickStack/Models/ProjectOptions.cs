namespace QuickStack.Models;

/// <summary>User-supplied options that control how the project is scaffolded.</summary>
public class ProjectOptions
{
    /// <summary>Sanitized project name (spaces → underscores, validated).</summary>
    public string ProjectName { get; set; } = "MyBackendApi";

    /// <summary>Directory where the project folder will be created.</summary>
    public string OutputDirectory { get; set; } = Directory.GetCurrentDirectory();

    /// <summary>Target database provider.</summary>
    public DatabaseType Database { get; set; } = DatabaseType.SqlServer;

    /// <summary>Additional features selected by the user.</summary>
    public List<FeatureType> SelectedFeatures { get; set; } = new();

    /// <summary>Authentication strategy.</summary>
    public AuthType AuthType { get; set; } = AuthType.None;

    /// <summary>Login identifier for authentication.</summary>
    public LoginIdentifier LoginIdentifier { get; set; } = LoginIdentifier.Email;

    /// <summary>Authentication sub-features (refresh tokens, email verification, 2FA).</summary>
    public List<AuthFeatures> AuthFeatures { get; set; } = new();

    /// <summary>Email provider for account verification.</summary>
    public EmailProvider EmailProvider { get; set; } = EmailProvider.Resend;
}
