using QuickStack.Models;
using Spectre.Console;

namespace QuickStack.UI;

/// <summary>Displays a summary table and asks the user to confirm before scaffolding.</summary>
public static class SummaryUI
{
    /// <summary>Renders a configuration summary and returns whether the user wants to proceed.</summary>
    /// <param name="projectoptions">The collected project options to display.</param>
    /// <returns><c>true</c> if the user confirmed; otherwise <c>false</c>.</returns>
    public static bool ConfirmAndDisplay(ProjectOptions projectoptions)
    {
        AnsiConsole.WriteLine();

        var table = new Table().Border(TableBorder.Rounded);
        table.AddColumn("[bold]Configurations[/]");
        table.AddColumn("[bold]Selected Options[/]");

        table.AddRow("Project Name", $"[bold cyan]{projectoptions.ProjectName}[/]");
        table.AddRow("Output Directory", $"[bold]{projectoptions.OutputDirectory}[/]");
        table.AddRow("Architecture", "Clean Architecture");
        table.AddRow("Authentication", projectoptions.AuthType switch
        {
            AuthType.IdentityWithJwt => "ASP.NET Identity + JWT",
            AuthType.CustomJwt => "Custom JWT",
            AuthType.None => "None",
            _ => projectoptions.AuthType.ToString()
        });

        if (projectoptions.AuthType != AuthType.None)
        {
            table.AddRow("Login Identifier", projectoptions.LoginIdentifier switch
            {
                LoginIdentifier.Email => "Email",
                LoginIdentifier.PhoneNumber => "Phone Number",
                LoginIdentifier.Both => "Email or Phone Number",
                LoginIdentifier.Username => "Username",
                _ => projectoptions.LoginIdentifier.ToString()
            });

            var authFeaturesText = projectoptions.AuthFeatures.Count > 0
                ? string.Join(", ", projectoptions.AuthFeatures.Select(f => f switch
                {
                    AuthFeatures.RefreshTokens => "Refresh Tokens",
                    AuthFeatures.AccountVerification => "Account Verification",
                    AuthFeatures.TwoFactorAuth => "2FA",
                    _ => f.ToString()
                }))
                : "None";
            table.AddRow("Auth Features", authFeaturesText);

            if (projectoptions.AuthFeatures.Contains(AuthFeatures.AccountVerification))
            {
                table.AddRow("Email Provider", projectoptions.EmailProvider switch
                {
                    EmailProvider.Resend => "Resend",
                    EmailProvider.GoogleGmail => "Google Gmail (SMTP)",
                    _ => projectoptions.EmailProvider.ToString()
                });
            }
        }

        var featuresText = projectoptions.SelectedFeatures.Count > 0
            ? string.Join(", ", projectoptions.SelectedFeatures.Select(f => f switch
            {
                FeatureType.JwtAuthentication => "JWT + Swagger",
                FeatureType.SerilogLogging => "Serilog",
                FeatureType.GlobalExceptionHandling => "Global Exception Handling",
                FeatureType.DockerSupport => "Docker",
                FeatureType.RateLimiting => "Rate Limiting",
                _ => f.ToString()
            }))
            : "None";

        table.AddRow("Selected Features", featuresText);

        AnsiConsole.Write(table);

        return AnsiConsole.Confirm("[bold green]Do you want to proceed with these configurations?[/]", true);
    }
}
