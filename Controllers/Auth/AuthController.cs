using expenseTracker.Core.Services.Auth.Interfaces;
using expenseTracker.Shared.DTOs.Auth;
using expenseTracker.Shared.DTOs.Common;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace expenseTracker.Core.Controllers.Auth
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly IAuthService _authService;
        private readonly ILogger<AuthController> _logger;

        public AuthController(IAuthService authService, ILogger<AuthController> logger)
        {
            _authService = authService;
            _logger = logger;
        }

        /// <summary>
        /// Authenticate user and generate JWT token
        /// </summary>
        [HttpPost("login")]
        [ProducesResponseType(typeof(ServiceResponseDto<AuthResponseDto>), 200)]
        [ProducesResponseType(typeof(ServiceResponseDto<object>), 400)]
        [ProducesResponseType(typeof(ServiceResponseDto<object>), 401)]
        public async Task<IActionResult> Login([FromBody] LoginRequestDto request)
        {
            try
            {
                var ipAddress = GetClientIpAddress();
                var result = await _authService.LoginAsync(request, ipAddress);

                if (result.Success)
                {
                    return Ok(result);
                }

                return BadRequest(result);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error in Login endpoint");
                return StatusCode(500, ServiceResponseDto<object>.ErrorResult("Internal server error"));
            }
        }

        /// <summary>
        /// Register a new user account
        /// </summary>
        [HttpPost("register")]
        [ProducesResponseType(typeof(ServiceResponseDto<AuthResponseDto>), 200)]
        [ProducesResponseType(typeof(ServiceResponseDto<object>), 400)]
        [ProducesResponseType(typeof(ServiceResponseDto<object>), 409)]
        public async Task<IActionResult> Register([FromBody] RegisterRequestDto request)
        {
            try
            {
                var ipAddress = GetClientIpAddress();
                var result = await _authService.RegisterAsync(request, ipAddress);

                if (result.Success)
                {
                    return Ok(result);
                }

                return BadRequest(result);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error in Register endpoint");
                return StatusCode(500, ServiceResponseDto<object>.ErrorResult("Internal server error"));
            }
        }

        /// <summary>
        /// Refresh JWT access token using refresh token
        /// </summary>
        [HttpPost("refresh")]
        [ProducesResponseType(typeof(ServiceResponseDto<AuthResponseDto>), 200)]
        [ProducesResponseType(typeof(ServiceResponseDto<object>), 400)]
        [ProducesResponseType(typeof(ServiceResponseDto<object>), 401)]
        public async Task<IActionResult> RefreshToken([FromBody] RefreshTokenRequestDto request)
        {
            try
            {
                var ipAddress = GetClientIpAddress();
                var result = await _authService.RefreshTokenAsync(request, ipAddress);

                if (result.Success)
                {
                    return Ok(result);
                }

                return Unauthorized(result);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error in RefreshToken endpoint");
                return StatusCode(500, ServiceResponseDto<object>.ErrorResult("Internal server error"));
            }
        }

        /// <summary>
        /// Logout user and revoke refresh token
        /// </summary>
        [HttpPost("logout")]
        [ProducesResponseType(typeof(ServiceResponseDto<bool>), 200)]
        [ProducesResponseType(typeof(ServiceResponseDto<object>), 400)]
        public async Task<IActionResult> Logout([FromBody] RefreshTokenRequestDto request)
        {
            try
            {
                var ipAddress = GetClientIpAddress();
                var result = await _authService.LogoutAsync(request.RefreshToken, ipAddress);
                return Ok(result);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error in Logout endpoint");
                return StatusCode(500, ServiceResponseDto<object>.ErrorResult("Internal server error"));
            }
        }

        /// <summary>
        /// Send password reset OTP to user's email
        /// </summary>
        [HttpPost("forgot-password")]
        [ProducesResponseType(typeof(ServiceResponseDto<bool>), 200)]
        [ProducesResponseType(typeof(ServiceResponseDto<object>), 400)]
        public async Task<IActionResult> ForgotPassword([FromBody] ForgotPasswordRequestDto request)
        {
            try
            {
                var ipAddress = GetClientIpAddress();
                var result = await _authService.ForgotPasswordAsync(request, ipAddress);
                return Ok(result);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error in ForgotPassword endpoint");
                return StatusCode(500, ServiceResponseDto<object>.ErrorResult("Internal server error"));
            }
        }

        /// <summary>
        /// Verify OTP for email verification
        /// </summary>
        [HttpPost("verify-otp")]
        [ProducesResponseType(typeof(ServiceResponseDto<bool>), 200)]
        [ProducesResponseType(typeof(ServiceResponseDto<object>), 400)]
        [ProducesResponseType(typeof(ServiceResponseDto<object>), 401)]
        public async Task<IActionResult> VerifyOtp([FromBody] VerifyOtpRequestDto request)
        {
            try
            {
                var result = await _authService.VerifyOtpAsync(request);

                if (result.Success)
                {
                    return Ok(result);
                }

                return BadRequest(result);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error in VerifyOtp endpoint");
                return StatusCode(500, ServiceResponseDto<object>.ErrorResult("Internal server error"));
            }
        }

        /// <summary>
        /// Reset password using OTP
        /// </summary>
        [HttpPost("reset-password")]
        [ProducesResponseType(typeof(ServiceResponseDto<bool>), 200)]
        [ProducesResponseType(typeof(ServiceResponseDto<object>), 400)]
        [ProducesResponseType(typeof(ServiceResponseDto<object>), 401)]
        public async Task<IActionResult> ResetPassword([FromBody] ResetPasswordRequestDto request)
        {
            try
            {
                var ipAddress = GetClientIpAddress();
                var result = await _authService.ResetPasswordAsync(request, ipAddress);

                if (result.Success)
                {
                    return Ok(result);
                }

                return BadRequest(result);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error in ResetPassword endpoint");
                return StatusCode(500, ServiceResponseDto<object>.ErrorResult("Internal server error"));
            }
        }

        /// <summary>
        /// Change password for authenticated user
        /// </summary>
        [HttpPost("change-password")]
        [ProducesResponseType(typeof(ServiceResponseDto<bool>), 200)]
        [ProducesResponseType(typeof(ServiceResponseDto<object>), 400)]
        [ProducesResponseType(typeof(ServiceResponseDto<object>), 401)]
        public async Task<IActionResult> ChangePassword([FromBody] dynamic request)
        {
            try
            {
                // Extract userId from request body (sent by Gateway)
                if (!int.TryParse(request.UserId?.ToString(), out int userId))
                {
                    return BadRequest(ServiceResponseDto<object>.ErrorResult("Invalid user session"));
                }

                var changePasswordRequest = new ChangePasswordRequestDto
                {
                    CurrentPassword = request.CurrentPassword,
                    NewPassword = request.NewPassword,
                    ConfirmPassword = request.ConfirmPassword
                };

                var result = await _authService.ChangePasswordAsync(userId, changePasswordRequest);

                if (result.Success)
                {
                    return Ok(result);
                }

                return BadRequest(result);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error in ChangePassword endpoint");
                return StatusCode(500, ServiceResponseDto<object>.ErrorResult("Internal server error"));
            }
        }

        /// <summary>
        /// Resend OTP to user's email
        /// </summary>
        [HttpPost("resend-otp")]
        [ProducesResponseType(typeof(ServiceResponseDto<bool>), 200)]
        [ProducesResponseType(typeof(ServiceResponseDto<object>), 400)]
        [ProducesResponseType(typeof(ServiceResponseDto<object>), 429)]
        public async Task<IActionResult> ResendOtp([FromBody] ResendOtpRequestDto request)
        {
            try
            {
                var ipAddress = GetClientIpAddress();
                var result = await _authService.ResendOtpAsync(request, ipAddress);

                if (result.Success)
                {
                    return Ok(result);
                }

                // Check if it's a rate limit error
                if (result.Message.Contains("wait", StringComparison.OrdinalIgnoreCase))
                {
                    return StatusCode(429, result); // Too Many Requests
                }

                return BadRequest(result);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error in ResendOtp endpoint");
                return StatusCode(500, ServiceResponseDto<object>.ErrorResult("Internal server error"));
            }
        }

        /// <summary>
        /// Get user profile information
        /// </summary>
        [HttpGet("profile")]
        [ProducesResponseType(typeof(ServiceResponseDto<UserDto>), 200)]
        [ProducesResponseType(typeof(ServiceResponseDto<object>), 401)]
        [ProducesResponseType(typeof(ServiceResponseDto<object>), 404)]
        public async Task<IActionResult> GetProfile([FromQuery] int userId)
        {
            try
            {
                var result = await _authService.GetUserProfileAsync(userId);

                if (result.Success)
                {
                    return Ok(result);
                }

                return NotFound(result);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error in GetProfile endpoint for user {UserId}", userId);
                return StatusCode(500, ServiceResponseDto<object>.ErrorResult("Internal server error"));
            }
        }

        private string? GetClientIpAddress()
        {
            try
            {
                // Check for forwarded IP first (from load balancer/proxy)
                var forwardedFor = Request.Headers["X-Forwarded-For"].FirstOrDefault();
                if (!string.IsNullOrEmpty(forwardedFor))
                {
                    return forwardedFor.Split(',').FirstOrDefault()?.Trim();
                }

                // Check for real IP
                var realIp = Request.Headers["X-Real-IP"].FirstOrDefault();
                if (!string.IsNullOrEmpty(realIp))
                {
                    return realIp;
                }

                // Fall back to connection remote IP
                return HttpContext.Connection.RemoteIpAddress?.ToString();
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Error getting client IP address");
                return null;
            }
        }
    }
}
