using QuickStack.Models;

namespace QuickStack.Services.Auth.Templates;

public static class EmailTemplates
{
    private static string P(ProjectOptions o) => o.ProjectName;

    public static string IEmailService(ProjectOptions o)
    {
        var p = P(o);
        return $$"""
namespace {{p}}.Application.Interfaces;

public interface IEmailService
{
    Task SendEmailAsync(string to, string subject, string body);
}
""";
    }

    public static string EmailSettings(ProjectOptions o)
    {
        var p = P(o);
        return $$"""
namespace {{p}}.Infrastructure.Services;

public class EmailSettings
{
    public const string SectionName = "EmailSettings";

    public string Provider { get; set; } = "{{(o.EmailProvider == EmailProvider.GoogleGmail ? "GoogleGmail" : "Resend")}}";
    public string ResendApiKey { get; set; } = string.Empty;
    public string SmtpServer { get; set; } = "smtp.gmail.com";
    public int SmtpPort { get; set; } = 465;
    public string SmtpUsername { get; set; } = string.Empty;
    public string SmtpPassword { get; set; } = string.Empty;
    public string SenderEmail { get; set; } = "noreply@{{o.ProjectName.ToLower()}}.com";
    public string SenderName { get; set; } = "{{o.ProjectName}}";
}
""";
    }

    public static string ResendService(ProjectOptions o)
    {
        var p = P(o);
        return $$"""
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using {{p}}.Application.Interfaces;
using Microsoft.Extensions.Options;

namespace {{p}}.Infrastructure.Services;

public class ResendEmailService : IEmailService
{
    private readonly EmailSettings _settings;
    private readonly IHttpClientFactory _httpClientFactory;

    public ResendEmailService(IOptions<EmailSettings> settings, IHttpClientFactory httpClientFactory)
    {
        _settings = settings.Value;
        _httpClientFactory = httpClientFactory;
    }

    public async Task SendEmailAsync(string to, string subject, string body)
    {
        using var client = _httpClientFactory.CreateClient();
        client.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue("Bearer", _settings.ResendApiKey);

        var payload = new
        {
            from = $"{_settings.SenderName} <{_settings.SenderEmail}>",
            to = new[] { to },
            subject,
            html = body
        };

        var json = JsonSerializer.Serialize(payload);
        var content = new StringContent(json, Encoding.UTF8, "application/json");

        var response = await client.PostAsync("https://api.resend.com/emails", content);
        response.EnsureSuccessStatusCode();
    }
}
""";
    }

    public static string GoogleGmailService(ProjectOptions o)
    {
        var p = P(o);
        return $$"""
using MailKit.Net.Smtp;
using MailKit.Security;
using MimeKit;
using MimeKit.Text;
using {{p}}.Application.Interfaces;
using Microsoft.Extensions.Options;

namespace {{p}}.Infrastructure.Services;

public class GoogleGmailEmailService : IEmailService
{
    private readonly EmailSettings _settings;

    public GoogleGmailEmailService(IOptions<EmailSettings> settings)
    {
        _settings = settings.Value;
    }

    public async Task SendEmailAsync(string to, string subject, string body)
    {
        var message = new MimeMessage();
        message.From.Add(new MailboxAddress(_settings.SenderName, _settings.SenderEmail));
        message.To.Add(MailboxAddress.Parse(to));
        message.Subject = subject;
        message.Body = new TextPart(TextFormat.Html) { Text = body };

        using var client = new SmtpClient();
        await client.ConnectAsync(_settings.SmtpServer, _settings.SmtpPort, SecureSocketOptions.SslOnConnect);
        await client.AuthenticateAsync(_settings.SmtpUsername, _settings.SmtpPassword);
        await client.SendAsync(message);
        await client.DisconnectAsync(true);
    }
}
""";
    }

    public static string EmailServiceExtensions(ProjectOptions o)
    {
        var p = P(o);
        var providerService = o.EmailProvider switch
        {
            EmailProvider.GoogleGmail => "GoogleGmailEmailService",
            _ => "ResendEmailService"
        };
        return $$"""
using {{p}}.Application.Interfaces;
using {{p}}.Infrastructure.Services;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace {{p}}.Infrastructure.DependencyInjection;

public static class EmailServiceExtensions
{
    public static IServiceCollection AddEmailServices(
        this IServiceCollection services,
        IConfiguration configuration)
    {
        services.Configure<EmailSettings>(
            configuration.GetSection(EmailSettings.SectionName));

        services.AddHttpClient();

        services.AddScoped<IEmailService, {{providerService}}>();

        return services;
    }
}
""";
    }
}
