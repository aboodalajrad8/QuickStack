using QuickStack.Models;

namespace QuickStack.Services.Auth.Templates;

public static class ApplicationServiceTemplates
{
    private static string P(ProjectOptions o) => o.ProjectName;

    public static string VerifyEmailRequest(ProjectOptions o)
    {
        var p = P(o);
        return $$"""
using System.ComponentModel.DataAnnotations;

namespace {{p}}.Application.DTOs.Auth;

public class VerifyEmailRequest
{
    [Required, EmailAddress]
    public string Email { get; set; } = string.Empty;

    [Required]
    public string Token { get; set; } = string.Empty;
}
""";
    }

    public static string VerifyEmailRequestValidator(ProjectOptions o)
    {
        var p = P(o);
        return $$"""
using FluentValidation;

namespace {{p}}.Application.DTOs.Auth;

public class VerifyEmailRequestValidator : AbstractValidator<VerifyEmailRequest>
{
    public VerifyEmailRequestValidator()
    {
        RuleFor(x => x.Email)
            .NotEmpty().WithMessage("Email is required.")
            .EmailAddress().WithMessage("A valid email address is required.");

        RuleFor(x => x.Token)
            .NotEmpty().WithMessage("Token is required.");
    }
}

public class ResendConfirmationRequestValidator : AbstractValidator<ResendConfirmationRequest>
{
    public ResendConfirmationRequestValidator()
    {
        RuleFor(x => x.Email)
            .NotEmpty().WithMessage("Email is required.")
            .EmailAddress().WithMessage("A valid email address is required.");
    }
}
""";
    }
}
