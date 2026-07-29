namespace QuickStack.Services.Auth.Models;

/// <summary>Represents a file to be written during project scaffolding.</summary>
/// <param name="RelativePath">Path relative to the project root (e.g. "src/Api/Program.cs").</param>
/// <param name="Content">Full text content to write to the file.</param>
public record GeneratedFile(string RelativePath, string Content);
