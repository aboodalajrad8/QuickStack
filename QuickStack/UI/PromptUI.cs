using QuickStack.Models;
using Spectre.Console;

namespace QuickStack.UI;

/// <summary>Interactive CLI prompts that collect project configuration from the user.</summary>
public static class PromptUI
{
    private static readonly HashSet<string> CsharpKeywords = new(StringComparer.OrdinalIgnoreCase)
    {
        "abstract", "as", "base", "bool", "break", "byte", "case", "catch", "char",
        "checked", "class", "const", "continue", "decimal", "default", "delegate",
        "do", "double", "else", "enum", "event", "explicit", "extern", "false",
        "finally", "fixed", "float", "for", "foreach", "goto", "if", "implicit",
        "in", "int", "interface", "internal", "is", "lock", "long", "namespace",
        "new", "null", "object", "operator", "out", "override", "params", "private",
        "protected", "public", "readonly", "ref", "return", "sbyte", "sealed",
        "short", "sizeof", "stackalloc", "static", "string", "struct", "switch",
        "this", "throw", "true", "try", "typeof", "uint", "ulong", "unchecked",
        "unsafe", "ushort", "using", "virtual", "void", "volatile", "while"
    };

    private static string SanitizeProjectName(string name)
    {
        var sanitized = name.Trim().Replace(' ', '_');
        return sanitized;
    }

    /// <summary>Runs the interactive prompts and returns the collected options.</summary>
    public static ProjectOptions CollectOptions()
    {
        var options = new ProjectOptions();

        var rawName = AnsiConsole.Ask<string>("Enter the [green]project name[/]:").Trim();
        while (true)
        {
            if (string.IsNullOrWhiteSpace(rawName))
            {
                rawName = AnsiConsole.Ask<string>("[red]Project name cannot be empty.[/] Enter the [green]project name[/]:").Trim();
                continue;
            }
            if (rawName.Any(c => Path.GetInvalidFileNameChars().Contains(c)))
            {
                rawName = AnsiConsole.Ask<string>("[red]Project name contains invalid characters.[/] Enter the [green]project name[/]:").Trim();
                continue;
            }
            if (char.IsDigit(rawName[0]))
            {
                rawName = AnsiConsole.Ask<string>("[red]Project name cannot start with a digit.[/] Enter the [green]project name[/]:").Trim();
                continue;
            }

            var testName = SanitizeProjectName(rawName);
            if (CsharpKeywords.Contains(testName))
            {
                rawName = AnsiConsole.Ask<string>($"[red]'{rawName}' is a C# reserved keyword.[/] Enter the [green]project name[/]:").Trim();
                continue;
            }
            break;
        }

        options.ProjectName = SanitizeProjectName(rawName);

        options.OutputDirectory = AnsiConsole.Ask<string>($"Enter the [green]output directory[/] ([grey]{options.OutputDirectory}[/]):")
            .Trim();
        if (string.IsNullOrWhiteSpace(options.OutputDirectory))
            options.OutputDirectory = Directory.GetCurrentDirectory();

        options.Database = AnsiConsole.Prompt(
            new SelectionPrompt<DatabaseType>()
                .Title("Select the [green]database[/]:")
                .UseConverter(db => db switch
                {
                    DatabaseType.SqlServer => "SQL Server",
                    DatabaseType.PostgreSql => "PostgreSQL",
                    DatabaseType.MySQL => "MySQL",
                    DatabaseType.Sqlite => "SQLite",
                    _ => db.ToString()
                })
                .AddChoices(
                    DatabaseType.SqlServer,
                    DatabaseType.PostgreSql,
                    DatabaseType.MySQL,
                    DatabaseType.Sqlite,
                    DatabaseType.None
                )
        );

        options.AuthType = AnsiConsole.Prompt(
            new SelectionPrompt<AuthType>()
                .Title("Select the [green]authentication type[/]:")
                .UseConverter(auth => auth switch
                {
                    AuthType.IdentityWithJwt => "ASP.NET Identity + JWT",
                    AuthType.CustomJwt => "Custom JWT (lightweight)",
                    AuthType.None => "None (no auth)",
                    _ => auth.ToString()
                })
                .AddChoices(AuthType.IdentityWithJwt, AuthType.CustomJwt, AuthType.None)
        );

        if (options.AuthType != AuthType.None)
        {
            options.LoginIdentifier = AnsiConsole.Prompt(
                new SelectionPrompt<LoginIdentifier>()
                    .Title("Select the [green]login identifier[/]:")
                    .UseConverter(id => id switch
                    {
                        LoginIdentifier.Email => "Email",
                        LoginIdentifier.PhoneNumber => "Phone Number",
                        LoginIdentifier.Both => "Email or Phone Number",
                        LoginIdentifier.Username => "Username",
                        _ => id.ToString()
                    })
                    .AddChoices(
                        LoginIdentifier.Email,
                        LoginIdentifier.PhoneNumber,
                        LoginIdentifier.Both,
                        LoginIdentifier.Username
                    )
            );

            options.AuthFeatures = AnsiConsole.Prompt(
                new MultiSelectionPrompt<AuthFeatures>()
                    .Title("Select [green]auth features[/]:")
                    .NotRequired()
                    .InstructionsText("[grey](Press [blue]<space>[/] to toggle, [green]<enter>[/] to accept)[/]")
                    .UseConverter(f => f switch
                    {
                        AuthFeatures.RefreshTokens => "Refresh Tokens",
                        AuthFeatures.AccountVerification => "Account Verification (Email Confirmation)",
                        AuthFeatures.TwoFactorAuth => "Two-Factor Authentication (2FA)",
                        _ => f.ToString()
                    })
                    .AddChoices(
                        AuthFeatures.RefreshTokens,
                        AuthFeatures.AccountVerification
                    )
            );

            if (options.AuthFeatures.Contains(AuthFeatures.AccountVerification))
            {
                options.EmailProvider = AnsiConsole.Prompt(
                    new SelectionPrompt<EmailProvider>()
                        .Title("Select the [green]email provider[/]:")
                        .UseConverter(p => p switch
                        {
                            EmailProvider.Resend => "Resend",
                            EmailProvider.GoogleGmail => "Google Gmail (SMTP)",
                            _ => p.ToString()
                        })
                        .AddChoices(EmailProvider.Resend, EmailProvider.GoogleGmail)
                );
            }
        }

        // When auth is enabled, JWT is always included — hide from feature list
        var hasAuth = options.AuthType != AuthType.None;
        var featureChoices = new List<FeatureType>
        {
            FeatureType.SerilogLogging,
            FeatureType.GlobalExceptionHandling,
            FeatureType.DockerSupport,
            FeatureType.RateLimiting
        };
        if (!hasAuth)
            featureChoices.Insert(0, FeatureType.JwtAuthentication);

        if (hasAuth)
            options.SelectedFeatures.Add(FeatureType.JwtAuthentication);

        var selectedFeatures = AnsiConsole.Prompt(
            new MultiSelectionPrompt<FeatureType>()
                .Title($"Select the [green]features[/]:{(hasAuth ? " ([grey]JWT included with auth[/])" : "")}")
                .NotRequired()
                .InstructionsText("[grey](Press [blue]<space>[/] to toggle a feature, [green]<enter>[/] to accept)[/]")
                .UseConverter(feature => feature switch
                {
                    FeatureType.JwtAuthentication => "JWT Authentication & Swagger Setup",
                    FeatureType.SerilogLogging => "Serilog Logging Integrations",
                    FeatureType.GlobalExceptionHandling => "Global Exception Handling Middleware",
                    FeatureType.RateLimiting => "Rate Limiting Middleware",
                    FeatureType.DockerSupport => "Docker & Docker-Compose Setup",
                    _ => feature.ToString()
                })
                .AddChoices(featureChoices)
        );

        options.SelectedFeatures.AddRange(selectedFeatures);

        return options;
    }
}
