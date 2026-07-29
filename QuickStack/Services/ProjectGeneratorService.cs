using System.Diagnostics;
using QuickStack.Models;
using QuickStack.Services.Auth;
using Spectre.Console;

namespace QuickStack.Services;

/// <summary>Orchestrates the full project scaffolding workflow.</summary>
public class ProjectGeneratorService
{
    private readonly ProjectOptions _options;
    private readonly string _projectDirectory;
    private readonly List<(string Title, Action Action)> _steps;

    /// <summary>Initializes the generator with user-provided options.</summary>
    /// <param name="options">The collected project configuration.</param>
    public ProjectGeneratorService(ProjectOptions options)
    {
        _options = options;
        _projectDirectory = Path.Combine(options.OutputDirectory, options.ProjectName);
        _steps =
        [
            ("Creating solution and projects...",     GenerateSolutionAndProjects),
            ("Generating folder structure...",         GenerateFolderStructure),
            ("Installing packages...",                 InstallPackages),
            ("Generating auth code...",                GenerateAuthCode),
            ("Cleaning up template stubs...",          CleanupTemplateStubs),
            ("Linking project references...",          LinkProjectReferences),
        ];
    }

    /// <summary>Runs all scaffolding steps in order with console progress output.</summary>
    public void Generate()
    {
        if (Directory.Exists(_projectDirectory))
        {
            AnsiConsole.MarkupLine($"[bold red]Error:[/] {_options.ProjectName} already exists at {_projectDirectory} !");
            return;
        }

        AnsiConsole.WriteLine();

        foreach (var (title, _) in _steps)
            AnsiConsole.MarkupLine($"[cyan]>[/] {title}");

        AnsiConsole.WriteLine();

        for (var i = 0; i < _steps.Count; i++)
        {
            var (title, action) = _steps[i];
            AnsiConsole.MarkupLine($"[cyan]> Step {i + 1}/{_steps.Count}:[/] {title}");
            action();
            AnsiConsole.WriteLine();
        }

        AnsiConsole.WriteLine();
        AnsiConsole.MarkupLine("[bold green]Project generated successfully![/]");
    }

    /// <summary>Creates the .sln file and four classlib/webapi projects via <c>dotnet new</c>.</summary>
    private void GenerateSolutionAndProjects()
    {
        var n = _options.ProjectName;
        Directory.CreateDirectory(_projectDirectory);

        RunDotnetCommand($@"new sln -n ""{n}""");

        RunDotnetCommand($@"new classlib -n ""{n}.Domain"" -o src/Domain");
        RunDotnetCommand($@"new classlib -n ""{n}.Application"" -o src/Application");
        RunDotnetCommand($@"new classlib -n ""{n}.Infrastructure"" -o src/Infrastructure");
        RunDotnetCommand($@"new webapi -n ""{n}.Api"" -o src/Api");

        RunDotnetCommand($@"sln add ""src/Domain/{n}.Domain.csproj"" --solution-folder ""Domain""");
        RunDotnetCommand($@"sln add ""src/Application/{n}.Application.csproj"" --solution-folder ""Application""");
        RunDotnetCommand($@"sln add ""src/Infrastructure/{n}.Infrastructure.csproj"" --solution-folder ""Infrastructure""");
        RunDotnetCommand($@"sln add ""src/Api/{n}.Api.csproj"" --solution-folder ""Api""");
    }

    /// <summary>Creates the Clean Architecture directory structure (Entities, DTOs, Persistence, etc.).</summary>
    private void GenerateFolderStructure()
    {
        void Create(string relative)
        {
            var path = Path.Combine(_projectDirectory, relative);
            Directory.CreateDirectory(path);
            AnsiConsole.MarkupLine($"   [green]+[/] [grey]{relative}/[/]");
        }

        Create("src/Domain/Entities");
        Create("src/Domain/Common");

        Create("src/Application/Interfaces");
        Create("src/Application/Services");
        Create("src/Application/DTOs/Auth");

        Create("src/Infrastructure/Persistence");
        Create("src/Infrastructure/Services");
        Create("src/Infrastructure/DependencyInjection");

        Create("src/Api/Controllers");
        Create("src/Api/Middlewares");
    }

    /// <summary>Generates auth source files via <see cref="AuthCodeGenerator"/> and writes them to disk.</summary>
    private void GenerateAuthCode()
    {
        if (_options.AuthType == AuthType.None)
        {
            AnsiConsole.MarkupLine("   [yellow]No authentication selected, skipping.[/]");
            return;
        }

        var generator = new AuthCodeGenerator(_options, _projectDirectory);
        var files = generator.Generate();

        foreach (var file in files)
        {
            var fullPath = Path.Combine(_projectDirectory, file.RelativePath);
            var parentDir = Path.GetDirectoryName(fullPath);
            if (!string.IsNullOrEmpty(parentDir) && !Directory.Exists(parentDir))
                Directory.CreateDirectory(parentDir);

            File.WriteAllText(fullPath, file.Content);
            AnsiConsole.MarkupLine($"   [green]+[/] [cyan]{file.RelativePath}[/]");
        }
    }

    /// <summary>Removes stub files left by <c>dotnet new</c> (Class1.cs, WeatherForecast.cs).</summary>
    private void CleanupTemplateStubs()
    {
        var stubs = new[]
        {
            "src/Domain/Class1.cs",
            "src/Application/Class1.cs",
            "src/Infrastructure/Class1.cs",
            "src/Api/WeatherForecast.cs",
        };

        foreach (var stub in stubs)
        {
            var path = Path.Combine(_projectDirectory, stub);
            if (File.Exists(path))
            {
                File.Delete(path);
                AnsiConsole.MarkupLine($"   [green]-[/] [grey]{stub}[/]");
            }
        }
    }

    /// <summary>Installs NuGet packages based on selected database, auth type, and features.</summary>
    private void InstallPackages()
    {
        var apiProject = Path.Combine(_projectDirectory, "src/Api",
            $"{_options.ProjectName}.Api.csproj");

        // Feature-only packages (always installed regardless of auth)
        if (_options.SelectedFeatures.Contains(FeatureType.SerilogLogging))
            InstallPackage(apiProject, "Serilog.AspNetCore");

        if (_options.AuthType == AuthType.None)
        {
            AnsiConsole.MarkupLine("   [yellow]No auth selected, skipping auth packages.[/]");
            return;
        }

        var infraProject = Path.Combine(_projectDirectory, "src/Infrastructure",
            $"{_options.ProjectName}.Infrastructure.csproj");

        // Fallback to Api project if Infrastructure project doesn't exist
        if (!File.Exists(infraProject))
        {
            infraProject = Path.Combine(_projectDirectory, "src/Api",
                $"{_options.ProjectName}.Api.csproj");
        }

        // EF Core package
        switch (_options.Database)
        {
            case DatabaseType.SqlServer:
                InstallPackage(infraProject, "Microsoft.EntityFrameworkCore.SqlServer");
                InstallPackage(infraProject, "Microsoft.EntityFrameworkCore.Tools");
                break;
            case DatabaseType.PostgreSql:
                InstallPackage(infraProject, "Npgsql.EntityFrameworkCore.PostgreSQL");
                break;
            case DatabaseType.Sqlite:
                InstallPackage(infraProject, "Microsoft.EntityFrameworkCore.Sqlite");
                break;
            case DatabaseType.MySQL:
                InstallPackage(infraProject, "Pomelo.EntityFrameworkCore.MySql");
                break;
        }

        // Auth-type-specific packages
        if (_options.AuthType == AuthType.IdentityWithJwt)
        {
            InstallPackage(infraProject, "Microsoft.AspNetCore.Identity.EntityFrameworkCore");
            InstallPackage(infraProject, "Microsoft.AspNetCore.Authentication.JwtBearer");
        }
        else if (_options.AuthType == AuthType.CustomJwt)
        {
            InstallPackage(infraProject, "Microsoft.AspNetCore.Authentication.JwtBearer");
            InstallPackage(infraProject, "BCrypt.Net-Next");
        }

        if (_options.AuthType != AuthType.None)
        {
            InstallPackage(infraProject, "System.IdentityModel.Tokens.Jwt");
        }

        // FluentValidation for DTO validation (installed to Application project for Clean Architecture, Api as fallback)
        if (_options.AuthFeatures.Contains(AuthFeatures.AccountVerification))
        {
            var appProject = Path.Combine(_projectDirectory, "src/Application",
                $"{_options.ProjectName}.Application.csproj");
            var fluentTarget = File.Exists(appProject) ? appProject : infraProject;
            InstallPackage(fluentTarget, "FluentValidation.DependencyInjectionExtensions");
        }

        // Email packages
        if (_options.AuthFeatures.Contains(AuthFeatures.AccountVerification)
            && _options.EmailProvider == EmailProvider.GoogleGmail)
        {
            InstallPackage(infraProject, "MailKit");
        }
    }

    /// <summary>Installs a single NuGet package with retry logic.</summary>
    private void InstallPackage(string project, string package)
    {
        AnsiConsole.Markup($"   [grey]nuget:[/] {package} ... ");

        bool success = false;
        for (int attempt = 0; attempt < 2; attempt++)
        {
            success = RunDotnetCommand($"add \"{project}\" package {package}", 120_000);
            if (success) break;
            if (attempt == 0)
                AnsiConsole.Markup(" [yellow]retrying...[/] ");
        }

        if (success)
            AnsiConsole.MarkupLine("[green]done[/]");
        else
            AnsiConsole.MarkupLine("[red]failed[/]");
    }

    /// <summary>Adds project-to-project references following Clean Architecture dependency rules.</summary>
    private void LinkProjectReferences()
    {
        var domain = $@"src/Domain/{_options.ProjectName}.Domain.csproj";
        var application = $@"src/Application/{_options.ProjectName}.Application.csproj";
        var infrastructure = $@"src/Infrastructure/{_options.ProjectName}.Infrastructure.csproj";
        var api = $@"src/Api/{_options.ProjectName}.Api.csproj";

        AnsiConsole.MarkupLine($"   [grey]add reference:[/] Application -> Domain");
        RunDotnetCommand($"add \"{application}\" reference \"{domain}\"");
        AnsiConsole.MarkupLine($"   [grey]add reference:[/] Infrastructure -> Application");
        RunDotnetCommand($"add \"{infrastructure}\" reference \"{application}\"");
        AnsiConsole.MarkupLine($"   [grey]add reference:[/] Api -> Infrastructure");
        RunDotnetCommand($"add \"{api}\" reference \"{infrastructure}\"");
    }

    /// <summary>Runs a <c>dotnet</c> CLI command with output capture and timeout.</summary>
    /// <param name="arguments">CLI arguments (without "dotnet" prefix).</param>
    /// <param name="timeoutMs">Timeout in milliseconds before killing the process.</param>
    /// <returns><c>true</c> if the process exited with code 0; otherwise <c>false</c>.</returns>
    private bool RunDotnetCommand(string arguments, int timeoutMs = 60_000)
    {
        var psi = new ProcessStartInfo
        {
            FileName = "dotnet",
            Arguments = arguments,
            WorkingDirectory = _projectDirectory,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true,
            StandardOutputEncoding = System.Text.Encoding.UTF8,
            StandardErrorEncoding = System.Text.Encoding.UTF8,
        };

        using var process = new Process { StartInfo = psi };
        var output = new System.Text.StringBuilder();
        var error = new System.Text.StringBuilder();

        process.OutputDataReceived += (_, e) =>
        {
            if (e.Data != null)
                output.AppendLine(e.Data);
        };
        process.ErrorDataReceived += (_, e) =>
        {
            if (e.Data != null)
                error.AppendLine(e.Data);
        };

        process.Start();
        process.BeginOutputReadLine();
        process.BeginErrorReadLine();

        if (process.WaitForExit(timeoutMs))
        {
            var exitCode = process.ExitCode;
            if (exitCode != 0)
            {
                var err = error.ToString().Trim();
                if (err.Length > 0)
                    AnsiConsole.MarkupLine($"\n      [red](exit code {exitCode})[/] [grey]{err.EscapeMarkup()}[/]");
            }
            return exitCode == 0;
        }
        else
        {
            process.Kill();
            AnsiConsole.MarkupLine("\n      [red](timed out after {0}s)[/]", timeoutMs / 1000);
            return false;
        }
    }
}
