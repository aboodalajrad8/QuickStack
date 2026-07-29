using Spectre.Console;

namespace QuickStack.UI;

/// <summary>Displays the application splash header.</summary>
public static class HeaderUI
{
    /// <summary>Renders the QuickStack figlet logo and version line to the console.</summary>
    public static void DisplayHeader()
    {
        AnsiConsole.Write(
            new FigletText("QuickStack")
                .Centered()
                .Color(Color.Cyan1)
        );
        AnsiConsole.WriteLine();
        AnsiConsole.MarkupLine("[bold grey]v1.0.0[/] - [green]Rapid .NET Backend Environment Generator[/]\n");
    }
}
