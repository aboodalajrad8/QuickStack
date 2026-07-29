using QuickStack.Models;

namespace QuickStack.Services.Auth.Templates;

public static class ExceptionHandlingTemplates
{
    private static string P(ProjectOptions o) => o.ProjectName;

    public static string ExceptionHandlingMiddleware(ProjectOptions o)
    {
        var p = P(o);
        return $$"""
using System.Net;
using System.Text.Json;

namespace {{p}}.Api.Middlewares;

public class ExceptionHandlingMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ILogger<ExceptionHandlingMiddleware> _logger;
    private readonly IHostEnvironment _env;

    public ExceptionHandlingMiddleware(
        RequestDelegate next,
        ILogger<ExceptionHandlingMiddleware> logger,
        IHostEnvironment env)
    {
        _next = next;
        _logger = logger;
        _env = env;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        try
        {
            await _next(context);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "An unhandled exception occurred.");
            await HandleExceptionAsync(context, ex);
        }
    }

    private Task HandleExceptionAsync(HttpContext context, Exception exception)
    {
        context.Response.ContentType = "application/json";

        var (statusCode, title) = exception switch
        {
            UnauthorizedAccessException => ((int)HttpStatusCode.Unauthorized, "Unauthorized"),
            ArgumentException => ((int)HttpStatusCode.BadRequest, "Validation failed"),
            KeyNotFoundException => ((int)HttpStatusCode.NotFound, "Resource not found"),
            _ => ((int)HttpStatusCode.InternalServerError, "An unexpected error occurred")
        };

        context.Response.StatusCode = statusCode;

        object problemDetails;
        if (_env.IsDevelopment())
        {
            problemDetails = new
            {
                status = statusCode,
                title,
                detail = exception.Message,
                stackTrace = exception.StackTrace
            };
        }
        else
        {
            problemDetails = new
            {
                status = statusCode,
                title
            };
        }

        var json = JsonSerializer.Serialize(problemDetails);
        return context.Response.WriteAsync(json);
    }
}
""";
    }

    public static string ExceptionMiddlewareExtension(ProjectOptions o)
    {
        var p = P(o);
        return $$"""
namespace {{p}}.Api.Middlewares;

public static class ExceptionHandlingMiddlewareExtensions
{
    public static IApplicationBuilder UseGlobalExceptionHandling(this IApplicationBuilder app)
    {
        return app.UseMiddleware<ExceptionHandlingMiddleware>();
    }
}
""";
    }
}
