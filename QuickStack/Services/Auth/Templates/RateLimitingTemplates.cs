using QuickStack.Models;

namespace QuickStack.Services.Auth.Templates;

public static class RateLimitingTemplates
{
    private static string P(ProjectOptions o) => o.ProjectName;

    public static string RateLimitingServices(ProjectOptions o)
    {
        var p = P(o);
        return $$"""
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.Extensions.DependencyInjection;
using System.Threading.RateLimiting;

namespace {{p}}.Api.Middlewares;

public static class RateLimitingServiceExtensions
{
    public static IServiceCollection AddRateLimitingServices(this IServiceCollection services)
    {
        services.AddRateLimiter(options =>
        {
            // General auth rate limiting (applied to all auth endpoints)
            options.AddFixedWindowLimiter("Auth", opt =>
            {
                opt.PermitLimit = 10;
                opt.Window = TimeSpan.FromMinutes(1);
                opt.QueueProcessingOrder = QueueProcessingOrder.OldestFirst;
                opt.QueueLimit = 0;
            });

            // Stricter limit for login to mitigate brute-force attacks
            options.AddFixedWindowLimiter("Login", opt =>
            {
                opt.PermitLimit = 5;
                opt.Window = TimeSpan.FromMinutes(1);
                opt.QueueProcessingOrder = QueueProcessingOrder.OldestFirst;
                opt.QueueLimit = 0;
            });

            // Refresh token rotation rate limit
            options.AddFixedWindowLimiter("Refresh", opt =>
            {
                opt.PermitLimit = 10;
                opt.Window = TimeSpan.FromMinutes(1);
                opt.QueueProcessingOrder = QueueProcessingOrder.OldestFirst;
                opt.QueueLimit = 0;
            });

            // Resend confirmation rate limit (slow down to prevent abuse)
            options.AddFixedWindowLimiter("ResendConfirmation", opt =>
            {
                opt.PermitLimit = 3;
                opt.Window = TimeSpan.FromMinutes(5);
                opt.QueueProcessingOrder = QueueProcessingOrder.OldestFirst;
                opt.QueueLimit = 0;
            });

            options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;

            options.OnRejected = async (context, cancellationToken) =>
            {
                context.HttpContext.Response.StatusCode = StatusCodes.Status429TooManyRequests;
                context.HttpContext.Response.ContentType = "application/json";

                var response = new
                {
                    status = 429,
                    title = "Too many requests",
                    detail = "Rate limit exceeded. Please try again later."
                };

                await context.HttpContext.Response.WriteAsync(
                    System.Text.Json.JsonSerializer.Serialize(response), cancellationToken);
            };
        });

        return services;
    }
}
""";
    }
}
