using QuickStack.Models;

namespace QuickStack.Services.Auth.Templates;

public static class DtoTemplates
{
    private static string P(ProjectOptions o) => o.ProjectName;

    public static string RegisterRequest(ProjectOptions o)
    {
        var p = P(o);
        var loginProp = o.LoginIdentifier switch
        {
            LoginIdentifier.Email => $$"""
    [Required, EmailAddress]
    public string Email { get; set; } = string.Empty;
""",
            LoginIdentifier.PhoneNumber => $$"""
    [Required, Phone]
    public string PhoneNumber { get; set; } = string.Empty;
""",
            LoginIdentifier.Both => $$"""
    [Required, EmailAddress]
    public string Email { get; set; } = string.Empty;

    [Phone]
    public string? PhoneNumber { get; set; }
""",
            LoginIdentifier.Username => $$"""
    [Required, StringLength(50, MinimumLength = 3)]
    public string Username { get; set; } = string.Empty;
""",
            _ => $$"""
    [Required, EmailAddress]
    public string Email { get; set; } = string.Empty;
"""
        };

        return $$"""
using System.ComponentModel.DataAnnotations;

namespace {{p}}.Application.DTOs.Auth;

public class RegisterRequest
{
    {{loginProp.TrimEnd()}}

    [Required, MinLength(8)]
    public string Password { get; set; } = string.Empty;

    [StringLength(100)]
    public string? FullName { get; set; }
}
""";
    }

    public static string LoginRequest(ProjectOptions o)
    {
        var p = P(o);
        var loginProp = o.LoginIdentifier switch
        {
            LoginIdentifier.Email => $$"""
    [Required, EmailAddress]
    public string Email { get; set; } = string.Empty;
""",
            LoginIdentifier.PhoneNumber => $$"""
    [Required, Phone]
    public string PhoneNumber { get; set; } = string.Empty;
""",
            LoginIdentifier.Both => $$"""
    [Required]
    public string LoginIdentifier { get; set; } = string.Empty;
""",
            LoginIdentifier.Username => $$"""
    [Required]
    public string Username { get; set; } = string.Empty;
""",
            _ => $$"""
    [Required, EmailAddress]
    public string Email { get; set; } = string.Empty;
"""
        };

        return $$"""
using System.ComponentModel.DataAnnotations;

namespace {{p}}.Application.DTOs.Auth;

public class LoginRequest
{
    {{loginProp.TrimEnd()}}

    [Required]
    public string Password { get; set; } = string.Empty;
}
""";
    }

    public static string RegisterResponse(ProjectOptions o)
    {
        var p = P(o);
        return $$"""
namespace {{p}}.Application.DTOs.Auth;

/// <summary>
/// Returned on successful registration.
/// Never contains tokens or sensitive fields.
/// The message is intentionally generic to prevent user enumeration.
/// </summary>
public class RegisterResponse
{
    public bool Success { get; set; }
    public string Message { get; set; } = string.Empty;
    public string? UserId { get; set; }
    public bool RequiresEmailConfirmation { get; set; }
}
""";
    }

    public static string LoginResponse(ProjectOptions o)
    {
        var p = P(o);
        return $$"""
namespace {{p}}.Application.DTOs.Auth;

/// <summary>
/// Returned on successful login.
/// The refresh token is delivered via HttpOnly cookie — never in the body.
/// </summary>
public class LoginResponse
{
    public string AccessToken { get; set; } = string.Empty;
    public int ExpiresIn { get; set; }
    public UserInfo User { get; set; } = new();
}

public class UserInfo
{
    public string Id { get; set; } = string.Empty;
    public string UserName { get; set; } = string.Empty;
    public string Email { get; set; } = string.Empty;
    public List<string> Roles { get; set; } = new();
}
""";
    }

    public static string ErrorResponse(ProjectOptions o)
    {
        var p = P(o);
        return $$"""
namespace {{p}}.Application.DTOs.Auth;

/// <summary>
/// Standard error response for auth endpoints.
/// Never reveals whether a user exists (prevents enumeration attacks).
/// </summary>
public class ErrorResponse
{
    public bool Success { get; set; }
    public string? ErrorCode { get; set; }
    public string Message { get; set; } = string.Empty;
}
""";
    }

    public static string ResendConfirmationRequest(ProjectOptions o)
    {
        var p = P(o);
        return $$"""
using System.ComponentModel.DataAnnotations;

namespace {{p}}.Application.DTOs.Auth;

public class ResendConfirmationRequest
{
    [Required, EmailAddress]
    public string Email { get; set; } = string.Empty;
}
""";
    }
}
