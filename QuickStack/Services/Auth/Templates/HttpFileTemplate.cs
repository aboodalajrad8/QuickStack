using System.Text;
using QuickStack.Models;

namespace QuickStack.Services.Auth.Templates;

public static class HttpFileTemplate
{
    public static string Generate(ProjectOptions o, string baseUrl)
    {
        var hasVerification = o.AuthFeatures.Contains(AuthFeatures.AccountVerification);
        var hasRefresh = o.AuthFeatures.Contains(AuthFeatures.RefreshTokens);

        var (registerField, loginField) = o.LoginIdentifier switch
        {
            LoginIdentifier.PhoneNumber => (
                "  \"phoneNumber\": \"+1234567890\",",
                "  \"phoneNumber\": \"+1234567890\","
            ),
            LoginIdentifier.Both => (
                "  \"email\": \"user@example.com\",\n  \"phoneNumber\": \"+1234567890\",",
                "  \"loginIdentifier\": \"user@example.com\","
            ),
            LoginIdentifier.Username => (
                "  \"username\": \"johndoe\",",
                "  \"username\": \"johndoe\","
            ),
            _ => (
                "  \"email\": \"user@example.com\",",
                "  \"email\": \"user@example.com\","
            )
        };

        var sb = new StringBuilder();
        sb.AppendLine($"@baseUrl = {baseUrl}");
        if (baseUrl == "https://localhost:5001")
            sb.AppendLine("# If the URL is incorrect, update @baseUrl above or check launchSettings.json");
        sb.AppendLine();
        sb.AppendLine("### Register");
        sb.AppendLine("POST {{baseUrl}}/api/auth/register");
        sb.AppendLine("Content-Type: application/json");
        sb.AppendLine();
        sb.AppendLine("{");
        sb.AppendLine(registerField);
        sb.AppendLine("  \"password\": \"string\",");
        sb.AppendLine("  \"fullName\": \"string\"");
        sb.AppendLine("}");
        sb.AppendLine();
        sb.AppendLine("### Login (access token in body, refresh token in HttpOnly cookie)");
        sb.AppendLine("POST {{baseUrl}}/api/auth/login");
        sb.AppendLine("Content-Type: application/json");
        sb.AppendLine();
        sb.AppendLine("{");
        sb.AppendLine(loginField);
        sb.AppendLine("  \"password\": \"string\"");
        sb.AppendLine("}");
        sb.AppendLine();
        sb.AppendLine("### Refresh Token (reads refresh token from HttpOnly cookie, no body required)");
        sb.AppendLine("POST {{baseUrl}}/api/auth/refresh");
        sb.AppendLine("Content-Type: application/json");
        sb.AppendLine();
        sb.AppendLine("### Logout (revokes current refresh token)");
        sb.AppendLine("POST {{baseUrl}}/api/auth/logout");
        sb.AppendLine("Authorization: Bearer YOUR_TOKEN_HERE");
        sb.AppendLine("Content-Type: application/json");
        sb.AppendLine();
        sb.AppendLine("### Logout from all devices");
        sb.AppendLine("POST {{baseUrl}}/api/auth/logout-all");
        sb.AppendLine("Authorization: Bearer YOUR_TOKEN_HERE");
        sb.AppendLine("Content-Type: application/json");
        sb.AppendLine();
        sb.AppendLine("### Get Current User");
        sb.AppendLine("GET {{baseUrl}}/api/auth/me");
        sb.AppendLine("Authorization: Bearer YOUR_TOKEN_HERE");
        sb.AppendLine();

        if (hasVerification)
        {
            sb.AppendLine("### Verify Email");
            sb.AppendLine("POST {{baseUrl}}/api/auth/verify-email");
            sb.AppendLine("Content-Type: application/json");
            sb.AppendLine();
            sb.AppendLine("{");
            sb.AppendLine("  \"email\": \"string\",");
            sb.AppendLine("  \"token\": \"string\"");
            sb.AppendLine("}");
            sb.AppendLine();
            sb.AppendLine("### Resend Confirmation Email");
            sb.AppendLine("POST {{baseUrl}}/api/auth/resend-confirmation");
            sb.AppendLine("Content-Type: application/json");
            sb.AppendLine();
            sb.AppendLine("{");
            sb.AppendLine("  \"email\": \"string\"");
            sb.AppendLine("}");
            sb.AppendLine();
        }

        return sb.ToString();
    }
}
