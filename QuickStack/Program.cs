using System.Diagnostics;
using QuickStack.Services;
using QuickStack.UI;
using Spectre.Console;

try
{
    return await Run();
}
catch (Exception ex)
{
    AnsiConsole.MarkupLine($"[red]Error:[/] {ex.Message.EscapeMarkup()}");
    return 1;
}

async Task<int> Run()
{
    var argsList = args.ToList();

    if (argsList.Count > 0 && argsList[0].Equals("permissions", StringComparison.OrdinalIgnoreCase))
    {
        return await RunPermissionsCommand(argsList.Skip(1).ToArray());
    }

    if (Console.IsInputRedirected)
    {
        AnsiConsole.MarkupLine("[yellow]QuickStack requires an interactive terminal.[/]");
        AnsiConsole.MarkupLine("Run it directly in a console window, or use: quickstack permissions <command>");
        return 1;
    }

    HeaderUI.DisplayHeader();

    var options = PromptUI.CollectOptions();

    if (!ValidateProjectName(options.ProjectName, out var sanitizedName, out var errorMsg))
    {
        AnsiConsole.MarkupLine($"[red]Error: {errorMsg}[/]");
        return 1;
    }
    options.ProjectName = sanitizedName;

    if (SummaryUI.ConfirmAndDisplay(options))
    {
        var generator = new ProjectGeneratorService(options);
        generator.Generate();
    }

    return 0;
}

/// <summary>Runs a permission management command against a scaffolded project.</summary>
/// <param name="args">The subcommand and its options.</param>
static async Task<int> RunPermissionsCommand(string[] args)
{
    if (args.Length == 0)
    {
        Console.Error.WriteLine("Usage: quickstack permissions <command> [options]");
        Console.Error.WriteLine();
        Console.Error.WriteLine("Commands:");
        Console.Error.WriteLine("  scan        Discover permissions from code (no DB writes)");
        Console.Error.WriteLine("  sync        Apply discovered permissions to database");
        Console.Error.WriteLine("  diff        Dry-run of sync (exits non-zero on drift)");
        Console.Error.WriteLine("  export      Export permissions (--format:json|csv|markdown)");
        Console.Error.WriteLine("  prune       Delete orphaned permissions (--yes to skip confirm)");
        Console.Error.WriteLine("  changelog   Print permission change log history");
        Console.Error.WriteLine();
        Console.Error.WriteLine("Options:");
        Console.Error.WriteLine("  --project-path <path>  Path to the scaffolded project (default: current dir)");
        Console.Error.WriteLine("  --grant-new-to-superadmin  Grant new permissions to SuperAdmin on sync");
        Console.Error.WriteLine("  --format:<format>     Output format for export (json, csv, markdown)");
        Console.Error.WriteLine("  --yes                 Skip confirmation prompt for prune");
        return 1;
    }

    var command = args[0].ToLowerInvariant();
    var projectPath = ResolveProjectPath(args);
    var additionalArgs = args.Skip(1).Where(a => !a.StartsWith("--project-path", StringComparison.OrdinalIgnoreCase)).ToArray();

    if (!Directory.Exists(projectPath))
    {
        Console.Error.WriteLine($"Error: Project path '{projectPath}' does not exist.");
        return 1;
    }

    var apiProjectDir = Path.Combine(projectPath, "src", "Api");
    if (!Directory.Exists(apiProjectDir))
    {
        apiProjectDir = projectPath;
    }

    var csproj = Directory.GetFiles(apiProjectDir, "*.csproj").FirstOrDefault();
    if (csproj == null)
    {
        Console.Error.WriteLine($"Error: No .csproj file found in '{apiProjectDir}'. Is this a QuickStack-generated project?");
        return 1;
    }

    var permissionArg = command switch
    {
        "scan" => "--permission:scan",
        "sync" => "--permission:sync",
        "diff" => "--permission:diff",
        "export" => "--permission:export",
        "prune" => "--permission:prune",
        "changelog" => "--permission:changelog",
        _ => null
    };

    if (permissionArg == null)
    {
        Console.Error.WriteLine($"Error: Unknown command '{command}'.");
        return 1;
    }

    var runArgs = new List<string> { "run", "--project", $"\"{csproj}\"", "--", permissionArg };
    runArgs.AddRange(additionalArgs.Select(a => a.Contains(' ') ? $"\"{a}\"" : a));

    Console.WriteLine($"Running: dotnet {string.Join(" ", runArgs)}");
    Console.WriteLine();

    var process = new Process
    {
        StartInfo = new ProcessStartInfo
        {
            FileName = "dotnet",
            Arguments = string.Join(" ", runArgs),
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true
        }
    };

    process.Start();
    var output = await process.StandardOutput.ReadToEndAsync();
    var error = await process.StandardError.ReadToEndAsync();
    await process.WaitForExitAsync();

    if (!string.IsNullOrEmpty(output)) Console.Write(output);
    if (!string.IsNullOrEmpty(error)) Console.Error.Write(error);

    return process.ExitCode;
}

/// <summary>Validates and sanitizes a project name (rejects C# keywords, empty names, leading digits, invalid filename characters).</summary>
/// <param name="name">The raw project name.</param>
/// <param name="sanitized">The sanitized name (spaces → underscores).</param>
/// <param name="error">Error message if validation fails.</param>
/// <returns><c>true</c> if the name is valid; otherwise <c>false</c>.</returns>
static bool ValidateProjectName(string name, out string sanitized, out string error)
{
    sanitized = name.Trim().Replace(' ', '_');
    error = "";

    if (string.IsNullOrWhiteSpace(sanitized))
    {
        error = "Project name cannot be empty.";
        return false;
    }
    if (sanitized.Any(c => Path.GetInvalidFileNameChars().Contains(c)))
    {
        error = "Project name contains invalid characters.";
        return false;
    }
    if (char.IsDigit(sanitized[0]))
    {
        error = "Project name cannot start with a digit.";
        return false;
    }

    var csharpKeywords = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
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

    if (csharpKeywords.Contains(sanitized))
    {
        error = $"'{name}' is a C# reserved keyword and cannot be used as a project name.";
        return false;
    }

    return true;
}

/// <summary>Extracts the --project-path argument value or returns the current directory.</summary>
static string ResolveProjectPath(string[] args)
{
    for (int i = 0; i < args.Length - 1; i++)
    {
        if (args[i].Equals("--project-path", StringComparison.OrdinalIgnoreCase))
        {
            return args[i + 1];
        }
    }
    return Directory.GetCurrentDirectory();
}
