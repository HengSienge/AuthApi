using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.Extensions.Logging;

namespace AuthApi.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class AccountController : ControllerBase
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly SignInManager<IdentityUser> _signInManager;
        private readonly IEmailSender _emailSender;
        private readonly IConfiguration _configuration;

        private readonly ILogger<AccountController> _logger;

        public AccountController(UserManager<IdentityUser> userManager, SignInManager<IdentityUser> signInManager, IConfiguration configuration, ILogger<AccountController> logger, IEmailSender emailSender)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _configuration = configuration;
            _logger = logger;
            _emailSender = emailSender;
        }

        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] RegisterModel model)
        {
            _logger.LogInformation("Attempting to register user with email: {Email}", model.Email);
            var user = new IdentityUser { UserName = model.Email, Email = model.Email };
            var result = await _userManager.CreateAsync(user, model.Password);
            if (result.Succeeded)
            {
                var token = GenerateJwtToken(user);
                _logger.LogInformation("User registered successfully: {Email}", model.Email);
                return Ok(new { Token = token });
            }
            _logger.LogWarning("User registration failed for email: {Email}. Errors: {Errors}", model.Email, string.Join(", ", result.Errors.Select(e => e.Description)));
            return BadRequest(result.Errors);
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginModel model)
        {
            _logger.LogInformation("Attempting login for user: {Email}", model.Email);
            var result = await _signInManager.PasswordSignInAsync(model.Email, model.Password, false, false);
            if (result.Succeeded)
            {
                var user = await _userManager.FindByEmailAsync(model.Email);
                if (user == null)
                {
                    _logger.LogWarning("User not found after successful login attempt: {Email}", model.Email);
                    return Unauthorized();
                }
                var token = GenerateJwtToken(user);
                _logger.LogInformation("User logged in successfully: {Email}", model.Email);
                return Ok(new { Token = token });
            }
            _logger.LogWarning("Login failed for user: {Email}", model.Email);
            return Unauthorized();
        }

        [HttpPost("confirm-email")]
        public async Task<IActionResult> ConfirmEmail([FromBody] ConfirmEmailModel model)
        {
            _logger.LogInformation("Attempting to confirm email for user ID: {UserId}", model.UserId);
            var user = await _userManager.FindByIdAsync(model.UserId);
            if (user == null)
            {
                _logger.LogWarning("User not found for email confirmation: {UserId}", model.UserId);
                return NotFound();
            }
            var result = await _userManager.ConfirmEmailAsync(user, model.Token);
            if (result.Succeeded)
            {
                _logger.LogInformation("Email confirmed successfully for user: {Email}", user.Email);
                return Ok();
            }
            _logger.LogWarning("Email confirmation failed for user: {Email}. Errors: {Errors}", user.Email, string.Join(", ", result.Errors.Select(e => e.Description)));
            return BadRequest(result.Errors);
        }
        
        [HttpPost("logout")]
        public async Task<IActionResult> Logout()
        {
            _logger.LogInformation("User logging out");
            await _signInManager.SignOutAsync();
            _logger.LogInformation("User logged out successfully");
            return Ok();
        }

        [HttpPost("forgot-password")]
        public async Task<IActionResult> ForgotPassword([FromBody] string email)
        {
            _logger.LogInformation("Forgot password request for email: {Email}", email);
            var user = await _userManager.FindByEmailAsync(email);
            if (user == null)
            {
                _logger.LogWarning("User not found for forgot password: {Email}", email);
                return NotFound();
            }
            var token = await _userManager.GeneratePasswordResetTokenAsync(user);
            var resetLink = Url.Action("ResetPassword", "Account", new { token, email}, Request.Scheme);
            await _emailSender.SendEmailAsync(user.Email!, "Reset Password", $"Please reset your password by clicking here: {resetLink}");
            _logger.LogInformation("Password reset email sent to: {Email}", email);
            return Ok();
        }

        [HttpPost("reset-password")]
        public async Task<IActionResult> ResetPassword([FromBody] ResetPasswordModel model)
        {
            _logger.LogInformation("Attempting password reset for email: {Email}", model.Email);
            var user = await _userManager.FindByEmailAsync(model.Email);
            if (user == null)
            {
                _logger.LogWarning("User not found for password reset: {Email}", model.Email);
                return NotFound();
            }
            var result = await _userManager.ResetPasswordAsync(user, model.Token, model.NewPassword);
            if (!result.Succeeded)
            {
                _logger.LogWarning("Password reset failed for email: {Email}. Errors: {Errors}", model.Email, string.Join(", ", result.Errors.Select(e => e.Description)));
                return BadRequest(result.Errors);
            }
            _logger.LogInformation("Password reset successfully for email: {Email}", model.Email);
            return Ok();
        }
        [HttpPost("change-password")]
        public async Task<IActionResult> ChangePassword([FromBody] ChangePasswordModel model)
        {
            var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
            if (userId == null)
            {
                _logger.LogWarning("Unauthorized attempt to change password");
                return Unauthorized();
            }
            _logger.LogInformation("Attempting password change for user ID: {UserId}", userId);
            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
            {
                _logger.LogWarning("User not found for password change: {UserId}", userId);
                return Unauthorized();
            }
            var result = await _userManager.ChangePasswordAsync(user, model.CurrentPassword, model.NewPassword);
            if (!result.Succeeded)
            {
                _logger.LogWarning("Password change failed for user: {Email}. Errors: {Errors}", user.Email, string.Join(", ", result.Errors.Select(e => e.Description)));
                return BadRequest(result.Errors);
            }
            _logger.LogInformation("Password changed successfully for user: {Email}", user.Email);
            return Ok();
        }
        private string GenerateJwtToken(IdentityUser user)
        {
            var claims = new[]
            {
                new Claim(JwtRegisteredClaimNames.Sub, user.Id ?? string.Empty),
                new Claim(JwtRegisteredClaimNames.Email, user.Email ?? string.Empty),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
            };
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JWT:Secret"] ?? throw new InvalidOperationException("JWT Secret not configured")));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
            var token = new JwtSecurityToken(
                issuer: _configuration["JWT:Issuer"],
                audience: _configuration["JWT:Audience"],
                claims: claims,
                expires: DateTime.Now.AddMinutes(30),
                signingCredentials: creds);
            return new JwtSecurityTokenHandler().WriteToken(token);
        }
    }
    public class ConfirmEmailModel
    {
        public required string UserId { get; set; }
        public required string Token { get; set; }
    }
    

    public class RegisterModel
    {
        public required string Email { get; set; }
        public required string Password { get; set; }
    }

    public class LoginModel
    {
        public required string Email { get; set; }
        public required string Password { get; set; }
    }

    public class ResetPasswordModel
    {
        public required string Email { get; set; }
        public required string Token { get; set; }
        public required string NewPassword { get; set; }
    }

    public class ChangePasswordModel
    {
        public required string CurrentPassword { get; set; }
        public required string NewPassword { get; set; }
    }
}