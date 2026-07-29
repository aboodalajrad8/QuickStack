using QuickStack.Models;

namespace QuickStack.Services.Auth.Templates;

public static class ControllerTemplates
{
    private static string P(ProjectOptions o) => o.ProjectName;

    private static string ExtraUsings(ProjectOptions o)
    {
        var usings = "";
        if (o.AuthFeatures.Contains(AuthFeatures.RefreshTokens))
        {
            usings += "using System.Security.Cryptography;\n";
        }
        return usings;
    }

    private static string IdentityRegisterBlock(ProjectOptions o) => o.LoginIdentifier switch
    {
        LoginIdentifier.Email => """
        var user = new AppUser
        {
            UserName = request.Email,
            Email = request.Email
        };
""",
        LoginIdentifier.PhoneNumber => """
        var user = new AppUser
        {
            UserName = request.PhoneNumber,
            PhoneNumber = request.PhoneNumber
        };
""",
        LoginIdentifier.Both => """
        var user = new AppUser
        {
            UserName = request.Email,
            Email = request.Email,
            PhoneNumber = request.PhoneNumber
        };
""",
        LoginIdentifier.Username => """
        var user = new AppUser
        {
            UserName = request.Username,
            Email = request.Username + "@placeholder.local"
        };
""",
        _ => """
        var user = new AppUser
        {
            UserName = request.Email,
            Email = request.Email
        };
"""
    };

    private static string IdentityRegisterFindBlock(ProjectOptions o) => o.LoginIdentifier switch
    {
        LoginIdentifier.Email => """
        var existingUser = await _userManager.FindByEmailAsync(request.Email);
""",
        LoginIdentifier.PhoneNumber => """
        var existingUser = await _userManager.FindByEmailAsync(request.PhoneNumber + "@placeholder.com");
""",
        LoginIdentifier.Both => """
        var existingUser = await _userManager.FindByEmailAsync(request.Email);
""",
        LoginIdentifier.Username => """
        var existingUser = await _userManager.FindByNameAsync(request.Username);
""",
        _ => """
        var existingUser = await _userManager.FindByEmailAsync(request.Email);
"""
    };

    private static string IdentityLoginFindBlock(ProjectOptions o) => o.LoginIdentifier switch
    {
        LoginIdentifier.Email => """
        var user = await _userManager.FindByEmailAsync(request.Email);
""",
        LoginIdentifier.PhoneNumber => """
        var user = await _context.Users.FirstOrDefaultAsync(u => u.PhoneNumber == request.PhoneNumber);
""",
        LoginIdentifier.Both => """
        var user = await _context.Users.FirstOrDefaultAsync(
            u => u.Email == request.LoginIdentifier || u.PhoneNumber == request.LoginIdentifier);
""",
        LoginIdentifier.Username => """
        var user = await _userManager.FindByNameAsync(request.Username);
""",
        _ => """
        var user = await _userManager.FindByEmailAsync(request.Email);
"""
    };

    private static string IdentityPasswordCheckBlock(ProjectOptions o) => o.LoginIdentifier switch
    {
        LoginIdentifier.Email or LoginIdentifier.Username => """
        var result = await _signInManager.CheckPasswordSignInAsync(user, request.Password, true);
        if (!result.Succeeded)
            return Unauthorized(new ErrorResponse { Success = false, ErrorCode = "INVALID_CREDENTIALS", Message = "Invalid email or password." });
""",
        LoginIdentifier.PhoneNumber or LoginIdentifier.Both => """
        var result = await _signInManager.CheckPasswordSignInAsync(user, request.Password, true);
        if (!result.Succeeded)
            return Unauthorized(new ErrorResponse { Success = false, ErrorCode = "INVALID_CREDENTIALS", Message = "Invalid email or password." });
""",
        _ => """
        var result = await _signInManager.CheckPasswordSignInAsync(user, request.Password, true);
        if (!result.Succeeded)
            return Unauthorized(new ErrorResponse { Success = false, ErrorCode = "INVALID_CREDENTIALS", Message = "Invalid email or password." });
"""
    };

    private static string IdentityClaimFields(ProjectOptions o) => o.LoginIdentifier switch
    {
        LoginIdentifier.Email => """
            new(ClaimTypes.Email, user.Email ?? "")
""",
        LoginIdentifier.PhoneNumber => """
            new(ClaimTypes.MobilePhone, user.PhoneNumber ?? ""),
            new(ClaimTypes.Email, user.Email ?? "")
""",
        LoginIdentifier.Both => """
            new(ClaimTypes.Email, user.Email ?? ""),
            new Claim("phone", user.PhoneNumber ?? "")
""",
        LoginIdentifier.Username => """
            new(ClaimTypes.Email, user.Email ?? ""),
            new(ClaimTypes.Name, user.UserName ?? "")
""",
        _ => """
            new(ClaimTypes.Email, user.Email ?? "")
"""
    };

    private static string IdentityGetRolesBlock => """
            var roles = (await _userManager.GetRolesAsync(user)).ToList();
""";

    private static string SetRefreshCookieBlock => """
        // Security: Refresh token delivered via HttpOnly, Secure, SameSite=Strict cookie.
        // Never stored in localStorage/sessionStorage to mitigate XSS token theft.
        var cookieOptions = new CookieOptions
        {
            HttpOnly = true,
            Secure = true,
            SameSite = SameSiteMode.Strict,
            Expires = refreshTokenExpiresAt,
            Path = "/api/auth"
        };
        Response.Cookies.Append("RefreshToken", refreshToken, cookieOptions);
""";

    // ─────────────────────────────────────────────────────────────────
    //  Identity AuthController
    // ─────────────────────────────────────────────────────────────────
    public static string AuthController(ProjectOptions o)
    {
        var p = P(o);
        var hasRefresh = o.AuthFeatures.Contains(AuthFeatures.RefreshTokens);
        var hasVerification = o.AuthFeatures.Contains(AuthFeatures.AccountVerification);

        var emailField = hasVerification
            ? "    private readonly IEmailService _emailService;\n"
            : "";
        var emailCtor = hasVerification
            ? "        IEmailService emailService,\n"
            : "";
        var emailAssign = hasVerification
            ? "        _emailService = emailService;\n"
            : "";

        var refreshField = hasRefresh
            ? "    private readonly IRefreshTokenService _refreshTokenService;\n    private readonly RefreshTokenSettings _refreshTokenSettings;\n"
            : "";

        var refreshCtor = hasRefresh
            ? "        IRefreshTokenService refreshTokenService,\n        IOptions<RefreshTokenSettings> refreshTokenSettings,\n"
            : "";

        var refreshAssign = hasRefresh
            ? "        _refreshTokenService = refreshTokenService;\n        _refreshTokenSettings = refreshTokenSettings.Value;\n"
            : "";

        var domainUsing = hasRefresh ? $"using {p}.Domain.Entities;\n" : "";

        return $$"""
using System.Security.Claims;
using {{p}}.Application.DTOs.Auth;
using {{p}}.Application.Interfaces;
using {{p}}.Infrastructure.Persistence;
using {{p}}.Infrastructure.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
{{domainUsing}}{{ExtraUsings(o)}}
namespace {{p}}.Api.Controllers;

[ApiController]
[Route("api/auth")]
[EnableRateLimiting("Auth")]
public class AuthController : ControllerBase
{
    private readonly UserManager<AppUser> _userManager;
    private readonly SignInManager<AppUser> _signInManager;
    private readonly ITokenService _tokenService;
    private readonly JwtSettings _jwtSettings;
    private readonly AppDbContext _context;
{{refreshField}}{{emailField}}
    public AuthController(
        UserManager<AppUser> userManager,
        SignInManager<AppUser> signInManager,
        ITokenService tokenService,
        IOptions<JwtSettings> jwtSettings,
        AppDbContext context,
{{refreshCtor}}{{emailCtor}}        ILogger<AuthController>? logger = null)
    {
        _userManager = userManager;
        _signInManager = signInManager;
        _tokenService = tokenService;
        _jwtSettings = jwtSettings.Value;
        _context = context;
{{refreshAssign}}{{emailAssign}}    }

    /// <summary>
    /// Registers a new user.
    /// Always returns the same generic message — never reveals whether the
    /// email is already registered (prevents user enumeration attacks).
    /// No tokens are issued on registration.
    /// </summary>
    [HttpPost("register")]
    public async Task<IActionResult> Register([FromBody] RegisterRequest request)
    {
        // Anti-enumeration: Check if user exists but return generic response either way
{{IdentityRegisterFindBlock(o)}}
        if (existingUser is not null)
        {
            return Ok(new RegisterResponse
            {
                Success = true,
                Message = "Account created. Please confirm your email to activate your account.",
                RequiresEmailConfirmation = {{(hasVerification ? "true" : "false")}}
            });
        }

{{IdentityRegisterBlock(o)}}
        if (!string.IsNullOrEmpty(request.FullName))
            user.FullName = request.FullName;

        var result = await _userManager.CreateAsync(user, request.Password);
        if (!result.Succeeded)
        {
            // Return generic success to avoid leaking whether email was already registered
            return Ok(new RegisterResponse
            {
                Success = true,
                Message = "Account created. Please confirm your email to activate your account.",
                RequiresEmailConfirmation = {{(hasVerification ? "true" : "false")}}
            });
        }

{{(hasVerification ? VerificationBlock(o) : "")}}
        return Ok(new RegisterResponse
        {
            Success = true,
            Message = "Account created. Please confirm your email to activate your account.",
            UserId = user.Id,
            RequiresEmailConfirmation = {{(hasVerification ? "true" : "false")}}
        });
    }

    /// <summary>
    /// Authenticates a user and issues tokens.
    /// Requires confirmed email if account verification is enabled.
    /// Access token is returned in the body; refresh token is set as an
    /// HttpOnly, Secure, SameSite=Strict cookie.
    /// </summary>
    [HttpPost("login")]
    [EnableRateLimiting("Login")]
    public async Task<IActionResult> Login([FromBody] LoginRequest request)
    {
{{IdentityLoginFindBlock(o)}}
        // Generic response to prevent user enumeration
        if (user is null)
            return Unauthorized(new ErrorResponse
            {
                Success = false,
                ErrorCode = "INVALID_CREDENTIALS",
                Message = "Invalid email or password."
            });

{{IdentityPasswordCheckBlock(o)}}
{{(hasVerification ? LoginEmailConfirmedCheck(o) : "")}}
        var claims = new List<Claim>
        {
            new(ClaimTypes.NameIdentifier, user.Id),
{{IdentityClaimFields(o)}}
        };

        var accessToken = _tokenService.GenerateToken(claims);
        var expiresIn = _jwtSettings.ExpiryInMinutes * 60;

{{IdentityGetRolesBlock}}
        var response = new LoginResponse
        {
            AccessToken = accessToken,
            ExpiresIn = expiresIn,
            User = new UserInfo
            {
                Id = user.Id,
                UserName = user.UserName ?? "",
                Email = user.Email ?? "",
                Roles = roles
            }
        };

{{(hasRefresh ? LoginRefreshBlock : "")}}
        return Ok(response);
    }

{{(hasRefresh ? BuildIdentityRefreshEndpoint(p, hasVerification) : "")}}
{{(hasVerification ? BuildVerificationEndpoints(p) : "")}}

    /// <summary>
    /// Returns the currently authenticated user's profile.
    /// </summary>
    [HttpGet("me")]
    [Authorize]
    public async Task<IActionResult> GetCurrentUser()
    {
        var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
        if (string.IsNullOrEmpty(userId))
            return NotFound(new ErrorResponse { Success = false, ErrorCode = "USER_NOT_FOUND", Message = "User not found." });
        var user = await _userManager.FindByIdAsync(userId);
        if (user is null)
            return NotFound(new ErrorResponse { Success = false, ErrorCode = "USER_NOT_FOUND", Message = "User not found." });

        var roles = await _userManager.GetRolesAsync(user);

        return Ok(new UserInfo
        {
            Id = user.Id,
            UserName = user.UserName ?? "",
            Email = user.Email ?? "",
            Roles = roles.ToList()
        });
    }
}
""";
    }

    // ─────────────────────────────────────────────────────────────────
    //  CustomJwt AuthController
    // ─────────────────────────────────────────────────────────────────
    public static string CustomJwtAuthController(ProjectOptions o)
    {
        var p = P(o);
        var hasRefresh = o.AuthFeatures.Contains(AuthFeatures.RefreshTokens);
        var hasVerification = o.AuthFeatures.Contains(AuthFeatures.AccountVerification);

        var registerFindByField = o.LoginIdentifier switch
        {
            LoginIdentifier.Email => "u => u.Email == request.Email || u.UserName == request.Email",
            LoginIdentifier.PhoneNumber => "u => u.PhoneNumber == request.PhoneNumber || u.UserName == request.PhoneNumber",
            LoginIdentifier.Both => "u => u.Email == request.Email || u.PhoneNumber == request.PhoneNumber || u.UserName == request.Email",
            LoginIdentifier.Username => "u => u.UserName == request.Username || u.Email == request.Username + \"@placeholder.com\"",
            _ => "u => u.Email == request.Email || u.UserName == request.Email"
        };

        var findByField = o.LoginIdentifier switch
        {
            LoginIdentifier.Email => "u => u.Email == request.Email",
            LoginIdentifier.PhoneNumber => "u => u.PhoneNumber == request.PhoneNumber",
            LoginIdentifier.Both => "u => u.Email == request.LoginIdentifier || u.PhoneNumber == request.LoginIdentifier",
            LoginIdentifier.Username => "u => u.UserName == request.Username",
            _ => "u => u.Email == request.Email"
        };

        var registerUserBlock = o.LoginIdentifier switch
        {
            LoginIdentifier.Email => """
            Email = request.Email,
            UserName = request.Email,
""",
            LoginIdentifier.PhoneNumber => """
            Email = request.PhoneNumber + "@placeholder.com",
            UserName = request.PhoneNumber,
            PhoneNumber = request.PhoneNumber,
""",
            LoginIdentifier.Both => """
            Email = request.Email,
            UserName = request.Email,
            PhoneNumber = request.PhoneNumber,
""",
            LoginIdentifier.Username => """
            Email = request.Username + "@placeholder.com",
            UserName = request.Username,
""",
            _ => """
            Email = request.Email,
            UserName = request.Email,
"""
        };

        var emailServiceField = hasVerification
            ? "\n    private readonly IEmailService _emailService;\n"
            : "";

        var emailServiceCtor = hasVerification
            ? "        IEmailService emailService,\n"
            : "";

        var refreshField = hasRefresh
            ? "    private readonly IRefreshTokenService _refreshTokenService;\n    private readonly RefreshTokenSettings _refreshTokenSettings;\n"
            : "";

        var refreshCtor = hasRefresh
            ? "        IRefreshTokenService refreshTokenService,\n        IOptions<RefreshTokenSettings> refreshTokenSettings,\n"
            : "";

        var refreshAssign = hasRefresh
            ? "        _refreshTokenService = refreshTokenService;\n        _refreshTokenSettings = refreshTokenSettings.Value;\n"
            : "";

        var emailServiceAssign = hasVerification
            ? "\n        _emailService = emailService;"
            : "";

        return $$"""
using System.Security.Claims;
using {{p}}.Application.DTOs.Auth;
using {{p}}.Application.Interfaces;
using {{p}}.Domain.Entities;
using {{p}}.Infrastructure.Persistence;
using {{p}}.Infrastructure.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
{{ExtraUsings(o)}}
namespace {{p}}.Api.Controllers;

[ApiController]
[Route("api/auth")]
[EnableRateLimiting("Auth")]
public class AuthController : ControllerBase
{
    private readonly AppDbContext _context;
    private readonly ITokenService _tokenService;
    private readonly JwtSettings _jwtSettings;
{{refreshField}}    private readonly IHttpContextAccessor? _httpContextAccessor;
{{emailServiceField}}
    public AuthController(
        AppDbContext context,
        ITokenService tokenService,
        IOptions<JwtSettings> jwtSettings,
{{refreshCtor}}{{emailServiceCtor}}        IHttpContextAccessor? httpContextAccessor = null)
    {
        _context = context;
        _tokenService = tokenService;
        _jwtSettings = jwtSettings.Value;
{{refreshAssign}}        _httpContextAccessor = httpContextAccessor;
{{emailServiceAssign}}    }

    /// <summary>
    /// Registers a new user.
    /// Always returns the same generic message — never reveals whether the
    /// email is already registered (prevents user enumeration attacks).
    /// No tokens are issued on registration.
    /// </summary>
    [HttpPost("register")]
    public async Task<IActionResult> Register([FromBody] RegisterRequest request)
    {
        // Anti-enumeration: Check if user exists but return generic response either way
        var existingUser = await _context.Set<User>()
            .FirstOrDefaultAsync({{registerFindByField}});
        if (existingUser is not null)
        {
            return Ok(new RegisterResponse
            {
                Success = true,
                Message = "Account created. Please confirm your email to activate your account.",
                RequiresEmailConfirmation = {{(hasVerification ? "true" : "false")}}
            });
        }

        var user = new User
        {
{{registerUserBlock}}            FullName = request.FullName,
            PasswordHash = BCrypt.Net.BCrypt.HashPassword(request.Password),
            CreatedAt = DateTime.UtcNow
        };

{{(hasVerification ? CustomJwtVerificationSetupBlock : "")}}
        _context.Set<User>().Add(user);
        await _context.SaveChangesAsync();

        return Ok(new RegisterResponse
        {
            Success = true,
            Message = "Account created. Please confirm your email to activate your account.",
            UserId = user.Id.ToString(),
            RequiresEmailConfirmation = {{(hasVerification ? "true" : "false")}}
        });
    }

    /// <summary>
    /// Authenticates a user and issues tokens.
    /// Requires confirmed email if account verification is enabled.
    /// Access token is returned in the body; refresh token is set as an
    /// HttpOnly, Secure, SameSite=Strict cookie.
    /// </summary>
    [HttpPost("login")]
    [EnableRateLimiting("Login")]
    public async Task<IActionResult> Login([FromBody] LoginRequest request)
    {
        var user = await _context.Set<User>()
            .FirstOrDefaultAsync({{findByField}});

        // Generic response to prevent user enumeration
        if (user is null)
            return Unauthorized(new ErrorResponse
            {
                Success = false,
                ErrorCode = "INVALID_CREDENTIALS",
                Message = "Invalid email or password."
            });

        if (!BCrypt.Net.BCrypt.Verify(request.Password, user.PasswordHash))
            return Unauthorized(new ErrorResponse
            {
                Success = false,
                ErrorCode = "INVALID_CREDENTIALS",
                Message = "Invalid email or password."
            });

{{(hasVerification ? CustomJwtLoginEmailConfirmedCheck : "")}}
        var claims = new List<Claim>
        {
            new(ClaimTypes.NameIdentifier, user.Id.ToString()),
            new(ClaimTypes.Email, user.Email),
            new(ClaimTypes.Name, user.UserName)
        };

        var accessToken = _tokenService.GenerateToken(claims);
        var expiresIn = _jwtSettings.ExpiryInMinutes * 60;

        var response = new LoginResponse
        {
            AccessToken = accessToken,
            ExpiresIn = expiresIn,
            User = new UserInfo
            {
                Id = user.Id.ToString(),
                UserName = user.UserName,
                Email = user.Email,
                Roles = new List<string>()
            }
        };

{{(hasRefresh ? CustomJwtLoginRefreshBlock : "")}}
        return Ok(response);
    }

{{(hasRefresh ? BuildCustomJwtRefreshEndpoint(p, hasVerification) : "")}}
{{(hasVerification ? BuildCustomJwtVerificationEndpoints(p) : "")}}

    /// <summary>
    /// Returns the currently authenticated user's profile.
    /// </summary>
    [HttpGet("me")]
    [Authorize]
    public async Task<IActionResult> GetCurrentUser()
    {
        var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
        if (string.IsNullOrEmpty(userId) || !Guid.TryParse(userId, out var parsedId))
            return NotFound(new ErrorResponse { Success = false, ErrorCode = "USER_NOT_FOUND", Message = "User not found." });

        var user = await _context.Set<User>().FindAsync(parsedId);
        if (user is null)
            return NotFound(new ErrorResponse { Success = false, ErrorCode = "USER_NOT_FOUND", Message = "User not found." });

        return Ok(new UserInfo
        {
            Id = user.Id.ToString(),
            UserName = user.UserName,
            Email = user.Email,
            Roles = new List<string>()
        });
    }
}
""";
    }

    // ─────────────────────────────────────────────────────────────────
    //  Shared helper blocks
    // ─────────────────────────────────────────────────────────────────

    private static string LoginRefreshBlock => """
        // Security: Issue refresh token as HttpOnly cookie (never in JSON body)
        var refreshToken = await _refreshTokenService.CreateAsync(
            user.Id,
            HttpContext.Connection.RemoteIpAddress?.ToString(),
            HttpContext.Request.Headers.UserAgent.ToString());

        var refreshTokenExpiresAt = DateTime.UtcNow.AddDays(_refreshTokenSettings.RefreshTokenExpirationDays);
        var cookieOptions = new CookieOptions
        {
            HttpOnly = true,
            Secure = true,
            SameSite = SameSiteMode.Strict,
            Expires = refreshTokenExpiresAt,
            Path = "/api/auth"
        };
        Response.Cookies.Append("RefreshToken", refreshToken, cookieOptions);
""";

    private static string CustomJwtLoginRefreshBlock => """
        // Security: Issue refresh token as HttpOnly cookie (never in JSON body)
        var refreshToken = await _refreshTokenService.CreateAsync(
            user.Id.ToString(),
            HttpContext.Connection.RemoteIpAddress?.ToString(),
            HttpContext.Request.Headers.UserAgent.ToString());

        var refreshTokenExpiresAt = DateTime.UtcNow.AddDays(_refreshTokenSettings.RefreshTokenExpirationDays);
        var cookieOptions = new CookieOptions
        {
            HttpOnly = true,
            Secure = true,
            SameSite = SameSiteMode.Strict,
            Expires = refreshTokenExpiresAt,
            Path = "/api/auth"
        };
        Response.Cookies.Append("RefreshToken", refreshToken, cookieOptions);
""";

    private static string VerificationBlock(ProjectOptions o)
    {
        if (!o.AuthFeatures.Contains(AuthFeatures.AccountVerification)) return "";

        var emailField = o.LoginIdentifier switch
        {
            LoginIdentifier.Email => "request.Email",
            LoginIdentifier.PhoneNumber => "request.PhoneNumber",
            LoginIdentifier.Both => "request.Email",
            LoginIdentifier.Username => "request.Username + \"@placeholder.local\"",
            _ => "request.Email"
        };

        return $$"""
        var emailToken = await _userManager.GenerateEmailConfirmationTokenAsync(user);
        // The confirmation email is sent asynchronously. In production, enqueue this
        // to a background job to avoid blocking the registration response.
        await _emailService.SendEmailAsync(
            {{emailField}},
            "Confirm your email",
            $"Please confirm your account using this token: {emailToken}");
""";
    }

    private static string LoginEmailConfirmedCheck(ProjectOptions o)
    {
        if (!o.AuthFeatures.Contains(AuthFeatures.AccountVerification)) return "";

        return """
        if (!await _userManager.IsEmailConfirmedAsync(user))
            return Unauthorized(new ErrorResponse
            {
                Success = false,
                ErrorCode = "EMAIL_NOT_CONFIRMED",
                Message = "Please confirm your email address before logging in."
            });
""";
    }

    private static string CustomJwtVerificationSetupBlock => """
        // Generate a random confirmation token
        user.EmailConfirmationToken = Guid.NewGuid().ToString("N");
""";

    private static string CustomJwtLoginEmailConfirmedCheck => """
        if (!user.EmailConfirmed)
            return Unauthorized(new ErrorResponse
            {
                Success = false,
                ErrorCode = "EMAIL_NOT_CONFIRMED",
                Message = "Please confirm your email address before logging in."
            });
""";

    // ─────────────────────────────────────────────────────────────────
    //  Identity Refresh Endpoint
    // ─────────────────────────────────────────────────────────────────
    private static string BuildIdentityRefreshEndpoint(string p, bool hasVerification)
    {
        return $$"""
    /// <summary>
    /// Refreshes the access token using the refresh token stored in the HttpOnly cookie.
    /// The refresh token is rotated on every use (old token revoked, new token issued).
    /// If a revoked token is reused, the entire token family is revoked (breach signal).
    /// </summary>
    [HttpPost("refresh")]
    [EnableRateLimiting("Refresh")]
    public async Task<IActionResult> Refresh()
    {
        // Security: Read refresh token from HttpOnly cookie, not from request body
        var rawRefreshToken = Request.Cookies["RefreshToken"];
        if (string.IsNullOrEmpty(rawRefreshToken))
            return Unauthorized(new ErrorResponse
            {
                Success = false,
                ErrorCode = "REFRESH_TOKEN_MISSING",
                Message = "No refresh token provided."
            });

        var result = await _refreshTokenService.ValidateAndRotateAsync(
            rawRefreshToken,
            HttpContext.Connection.RemoteIpAddress?.ToString(),
            HttpContext.Request.Headers.UserAgent.ToString());

        if (!result.Success)
        {
            // Clear the stale cookie
            Response.Cookies.Delete("RefreshToken", new CookieOptions
            {
                HttpOnly = true,
                Secure = true,
                SameSite = SameSiteMode.Strict,
                Path = "/api/auth"
            });

            var errorCode = result.IsBreachDetected ? "TOKEN_REUSE_DETECTED" : "INVALID_REFRESH_TOKEN";
            return Unauthorized(new ErrorResponse
            {
                Success = false,
                ErrorCode = errorCode,
                Message = result.IsBreachDetected
                    ? "Security breach detected. All tokens for this session have been revoked."
                    : result.ErrorMessage ?? "Invalid refresh token."
            });
        }

        // Issue a new access token
        var user = await _userManager.FindByIdAsync(result.UserId!);
        if (user is null)
            return Unauthorized(new ErrorResponse
            {
                Success = false,
                ErrorCode = "USER_NOT_FOUND",
                Message = "User not found."
            });

        var claims = new List<Claim>
        {
            new(ClaimTypes.NameIdentifier, user.Id),
            new(ClaimTypes.Email, user.Email ?? "")
        };

        var accessToken = _tokenService.GenerateToken(claims);
        var expiresIn = _jwtSettings.ExpiryInMinutes * 60;

        // Set the new refresh token as HttpOnly cookie
        var cookieOptions = new CookieOptions
        {
            HttpOnly = true,
            Secure = true,
            SameSite = SameSiteMode.Strict,
            Expires = result.NewRefreshTokenExpiresAt,
            Path = "/api/auth"
        };
        Response.Cookies.Append("RefreshToken", result.NewRefreshToken!, cookieOptions);

        return Ok(new { accessToken, expiresIn });
    }

    /// <summary>
    /// Revokes the current refresh token (logout from this device).
    /// </summary>
    [HttpPost("logout")]
    [Authorize]
    public async Task<IActionResult> Logout()
    {
        var rawRefreshToken = Request.Cookies["RefreshToken"];
        if (!string.IsNullOrEmpty(rawRefreshToken))
        {
            await _refreshTokenService.RevokeAsync(rawRefreshToken);
        }

        Response.Cookies.Delete("RefreshToken", new CookieOptions
        {
            HttpOnly = true,
            Secure = true,
            SameSite = SameSiteMode.Strict,
            Path = "/api/auth"
        });

        return Ok(new { message = "Logged out successfully." });
    }

    /// <summary>
    /// Revokes all refresh tokens for the current user (logout from all devices).
    /// </summary>
    [HttpPost("logout-all")]
    [Authorize]
    public async Task<IActionResult> LogoutAll()
    {
        var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
        if (!string.IsNullOrEmpty(userId))
        {
            await _refreshTokenService.RevokeAllForUserAsync(userId);
        }

        Response.Cookies.Delete("RefreshToken", new CookieOptions
        {
            HttpOnly = true,
            Secure = true,
            SameSite = SameSiteMode.Strict,
            Path = "/api/auth"
        });

        return Ok(new { message = "Logged out from all devices successfully." });
    }

""";
    }

    // ─────────────────────────────────────────────────────────────────
    //  CustomJwt Refresh Endpoint
    // ─────────────────────────────────────────────────────────────────
    private static string BuildCustomJwtRefreshEndpoint(string p, bool hasVerification)
    {
        return $$"""
    /// <summary>
    /// Refreshes the access token using the refresh token stored in the HttpOnly cookie.
    /// The refresh token is rotated on every use (old token revoked, new token issued).
    /// If a revoked token is reused, the entire token family is revoked (breach signal).
    /// </summary>
    [HttpPost("refresh")]
    [EnableRateLimiting("Refresh")]
    public async Task<IActionResult> Refresh()
    {
        // Security: Read refresh token from HttpOnly cookie, not from request body
        var rawRefreshToken = Request.Cookies["RefreshToken"];
        if (string.IsNullOrEmpty(rawRefreshToken))
            return Unauthorized(new ErrorResponse
            {
                Success = false,
                ErrorCode = "REFRESH_TOKEN_MISSING",
                Message = "No refresh token provided."
            });

        var result = await _refreshTokenService.ValidateAndRotateAsync(
            rawRefreshToken,
            HttpContext.Connection.RemoteIpAddress?.ToString(),
            HttpContext.Request.Headers.UserAgent.ToString());

        if (!result.Success)
        {
            Response.Cookies.Delete("RefreshToken", new CookieOptions
            {
                HttpOnly = true,
                Secure = true,
                SameSite = SameSiteMode.Strict,
                Path = "/api/auth"
            });

            var errorCode = result.IsBreachDetected ? "TOKEN_REUSE_DETECTED" : "INVALID_REFRESH_TOKEN";
            return Unauthorized(new ErrorResponse
            {
                Success = false,
                ErrorCode = errorCode,
                Message = result.IsBreachDetected
                    ? "Security breach detected. All tokens for this session have been revoked."
                    : result.ErrorMessage ?? "Invalid refresh token."
            });
        }

        if (!Guid.TryParse(result.UserId, out var parsedUid))
            return Unauthorized(new ErrorResponse
            {
                Success = false,
                ErrorCode = "INVALID_USER_ID",
                Message = "Invalid user identifier in token."
            });

        var user = await _context.Set<User>().FindAsync(parsedUid);
        if (user is null)
            return Unauthorized(new ErrorResponse
            {
                Success = false,
                ErrorCode = "USER_NOT_FOUND",
                Message = "User not found."
            });

        var claims = new List<Claim>
        {
            new(ClaimTypes.NameIdentifier, user.Id.ToString()),
            new(ClaimTypes.Email, user.Email)
        };

        var accessToken = _tokenService.GenerateToken(claims);
        var expiresIn = _jwtSettings.ExpiryInMinutes * 60;

        var cookieOptions = new CookieOptions
        {
            HttpOnly = true,
            Secure = true,
            SameSite = SameSiteMode.Strict,
            Expires = result.NewRefreshTokenExpiresAt,
            Path = "/api/auth"
        };
        Response.Cookies.Append("RefreshToken", result.NewRefreshToken!, cookieOptions);

        return Ok(new { accessToken, expiresIn });
    }

    /// <summary>
    /// Revokes the current refresh token (logout from this device).
    /// </summary>
    [HttpPost("logout")]
    [Authorize]
    public async Task<IActionResult> Logout()
    {
        var rawRefreshToken = Request.Cookies["RefreshToken"];
        if (!string.IsNullOrEmpty(rawRefreshToken))
        {
            await _refreshTokenService.RevokeAsync(rawRefreshToken);
        }

        Response.Cookies.Delete("RefreshToken", new CookieOptions
        {
            HttpOnly = true,
            Secure = true,
            SameSite = SameSiteMode.Strict,
            Path = "/api/auth"
        });

        return Ok(new { message = "Logged out successfully." });
    }

    /// <summary>
    /// Revokes all refresh tokens for the current user (logout from all devices).
    /// </summary>
    [HttpPost("logout-all")]
    [Authorize]
    public async Task<IActionResult> LogoutAll()
    {
        var uid = User.FindFirstValue(ClaimTypes.NameIdentifier);
        if (!string.IsNullOrEmpty(uid))
        {
            await _refreshTokenService.RevokeAllForUserAsync(uid);
        }

        Response.Cookies.Delete("RefreshToken", new CookieOptions
        {
            HttpOnly = true,
            Secure = true,
            SameSite = SameSiteMode.Strict,
            Path = "/api/auth"
        });

        return Ok(new { message = "Logged out from all devices successfully." });
    }

""";
    }

    // ─────────────────────────────────────────────────────────────────
    //  Identity Verification Endpoints
    // ─────────────────────────────────────────────────────────────────
    private static string BuildVerificationEndpoints(string p)
    {
        return $$"""
    /// <summary>
    /// Confirms a user's email address using the token sent during registration.
    /// </summary>
    [HttpPost("verify-email")]
    public async Task<IActionResult> VerifyEmail([FromBody] VerifyEmailRequest request)
    {
        var user = await _userManager.FindByEmailAsync(request.Email);
        if (user is null)
            return Ok(new { message = "If the email exists, it has been verified." });

        var result = await _userManager.ConfirmEmailAsync(user, request.Token);
        if (!result.Succeeded)
            return BadRequest(new ErrorResponse
            {
                Success = false,
                ErrorCode = "VERIFICATION_FAILED",
                Message = "Email verification failed. The token may be invalid or expired."
            });

        return Ok(new { message = "Email verified successfully." });
    }

    /// <summary>
    /// Resends the email confirmation link.
    /// Always returns the same generic message to prevent email enumeration.
    /// </summary>
    [HttpPost("resend-confirmation")]
    [EnableRateLimiting("ResendConfirmation")]
    public async Task<IActionResult> ResendConfirmation([FromBody] ResendConfirmationRequest request)
    {
        var user = await _userManager.FindByEmailAsync(request.Email);
        if (user is null)
            return Ok(new { message = "If the email exists, a confirmation link has been sent." });

        if (await _userManager.IsEmailConfirmedAsync(user))
            return Ok(new { message = "If the email exists, a confirmation link has been sent." });

        var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);
        await _emailService.SendEmailAsync(request.Email, "Confirm your email",
            $"Please confirm your account using this token: {token}");

        return Ok(new { message = "If the email exists, a confirmation link has been sent." });
    }

""";
    }

    // ─────────────────────────────────────────────────────────────────
    //  CustomJwt Verification Endpoints
    // ─────────────────────────────────────────────────────────────────
    private static string BuildCustomJwtVerificationEndpoints(string p)
    {
        return $$"""
    /// <summary>
    /// Confirms a user's email address using the token sent during registration.
    /// </summary>
    [HttpPost("verify-email")]
    public async Task<IActionResult> VerifyEmail([FromBody] VerifyEmailRequest request)
    {
        var user = await _context.Set<User>()
            .FirstOrDefaultAsync(u => u.Email == request.Email);
        if (user is null)
            return Ok(new { message = "If the email exists, it has been verified." });

        if (user.EmailConfirmationToken != request.Token)
            return BadRequest(new ErrorResponse
            {
                Success = false,
                ErrorCode = "VERIFICATION_FAILED",
                Message = "Email verification failed. The token may be invalid or expired."
            });

        user.EmailConfirmed = true;
        user.EmailConfirmationToken = null;
        await _context.SaveChangesAsync();

        return Ok(new { message = "Email verified successfully." });
    }

    /// <summary>
    /// Resends the email confirmation link.
    /// Always returns the same generic message to prevent email enumeration.
    /// </summary>
    [HttpPost("resend-confirmation")]
    [EnableRateLimiting("ResendConfirmation")]
    public async Task<IActionResult> ResendConfirmation([FromBody] ResendConfirmationRequest request)
    {
        var user = await _context.Set<User>()
            .FirstOrDefaultAsync(u => u.Email == request.Email);
        if (user is null)
            return Ok(new { message = "If the email exists, a confirmation link has been sent." });

        if (user.EmailConfirmed)
            return Ok(new { message = "If the email exists, a confirmation link has been sent." });

        user.EmailConfirmationToken = Guid.NewGuid().ToString("N");
        await _context.SaveChangesAsync();

        await _emailService.SendEmailAsync(request.Email, "Confirm your email",
            $"Please confirm your account using this token: {user.EmailConfirmationToken}");

        return Ok(new { message = "If the email exists, a confirmation link has been sent." });
    }

""";
    }
}
