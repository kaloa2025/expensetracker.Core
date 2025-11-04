using AutoMapper;
using expenseTracker.Core.Data;
using expenseTracker.Core.Models.Auth;
using expenseTracker.Core.Services.Auth.Interfaces;
using expenseTracker.Shared.DTOs.Auth;
using expenseTracker.Shared.DTOs.Common;
using expenseTracker.Shared.Enums;
using Microsoft.EntityFrameworkCore;

namespace expenseTracker.Core.Services.Auth
{
    public class AuthService : IAuthService
    {
        private readonly CoreDbContext _context;
        private readonly IJwtService _jwtService;
        private readonly IOtpService _otpService;
        private readonly IEmailService _emailService;
        private readonly IMapper _mapper;
        private readonly ILogger<AuthService> _logger;

        public AuthService(
            CoreDbContext context,
            IJwtService jwtService,
            IOtpService otpService,
            IEmailService emailService,
            IMapper mapper,
            ILogger<AuthService> logger)
        {
            _context = context;
            _jwtService = jwtService;
            _otpService = otpService;
            _emailService = emailService;
            _mapper = mapper;
            _logger = logger;
        }

        public async Task<ServiceResponseDto<AuthResponseDto>> LoginAsync(LoginRequestDto request, string? ipAddress = null)
        {
            try
            {
                _logger.LogInformation("Login attempt for email: {Email}", request.Email);

                var user = await _context.Users
                    .FirstOrDefaultAsync(u => u.Email == request.Email && u.IsActive);

                if (user == null || !BCrypt.Net.BCrypt.Verify(request.Password, user.PasswordHash))
                {
                    _logger.LogWarning("Login failed for email: {Email} - Invalid credentials", request.Email);
                    return ServiceResponseDto<AuthResponseDto>.ErrorResult("Invalid email or password");
                }

                // Update last login
                user.LastLoginAt = DateTime.UtcNow;

                // Generate tokens
                var accessToken = _jwtService.GenerateAccessToken(user);
                var refreshToken = _jwtService.GenerateRefreshToken();

                // Save refresh token
                var refreshTokenEntity = new RefreshToken
                {
                    Token = refreshToken,
                    UserId = user.Id,
                    ExpiresAt = DateTime.UtcNow.AddDays(7),
                    RevokedByIp = ipAddress
                };

                _context.RefreshTokens.Add(refreshTokenEntity);
                await _context.SaveChangesAsync();

                var authResponse = new AuthResponseDto
                {
                    Token = accessToken,
                    RefreshToken = refreshToken,
                    ExpiresAt = DateTime.UtcNow.AddHours(1),
                    User = _mapper.Map<UserDto>(user),
                    RequiresEmailVerification = !user.IsEmailVerified
                };

                _logger.LogInformation("Login successful for user: {UserId}", user.Id);

                return ServiceResponseDto<AuthResponseDto>.SuccessResult(authResponse, "Login successful");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error during login for email: {Email}", request.Email);
                return ServiceResponseDto<AuthResponseDto>.ErrorResult("An error occurred during login");
            }
        }

        public async Task<ServiceResponseDto<AuthResponseDto>> RegisterAsync(RegisterRequestDto request, string? ipAddress = null)
        {
            try
            {
                _logger.LogInformation("Registration attempt for email: {Email}", request.Email);

                // Check if user already exists
                if (await _context.Users.AnyAsync(u => u.Email == request.Email))
                {
                    _logger.LogWarning("Registration failed for email: {Email} - User already exists", request.Email);
                    return ServiceResponseDto<AuthResponseDto>.ErrorResult("User with this email already exists");
                }

                // Create new user
                var user = new User
                {
                    Email = request.Email,
                    UserName = request.UserName,
                    PasswordHash = BCrypt.Net.BCrypt.HashPassword(request.Password),
                    IsEmailVerified = false,
                    IsActive = true
                };

                _context.Users.Add(user);
                await _context.SaveChangesAsync();

                // Generate OTP for email verification
                var otp = await _otpService.GenerateOtpAsync(user.Id, user.Email, OtpTypes.EmailVerification, ipAddress);

                // Send verification email
                await _emailService.SendEmailVerificationAsync(user.Email, user.UserName, otp);

                // Generate tokens
                var accessToken = _jwtService.GenerateAccessToken(user);
                var refreshToken = _jwtService.GenerateRefreshToken();

                // Save refresh token
                var refreshTokenEntity = new RefreshToken
                {
                    Token = refreshToken,
                    UserId = user.Id,
                    ExpiresAt = DateTime.UtcNow.AddDays(7),
                    RevokedByIp = ipAddress
                };

                _context.RefreshTokens.Add(refreshTokenEntity);
                await _context.SaveChangesAsync();

                var authResponse = new AuthResponseDto
                {
                    Token = accessToken,
                    RefreshToken = refreshToken,
                    ExpiresAt = DateTime.UtcNow.AddHours(1),
                    User = _mapper.Map<UserDto>(user),
                    RequiresEmailVerification = true
                };

                _logger.LogInformation("Registration successful for user: {UserId}", user.Id);

                return ServiceResponseDto<AuthResponseDto>.SuccessResult(authResponse, "Registration successful. Please verify your email.");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error during registration for email: {Email}", request.Email);
                return ServiceResponseDto<AuthResponseDto>.ErrorResult("An error occurred during registration");
            }
        }

        public async Task<ServiceResponseDto<AuthResponseDto>> RefreshTokenAsync(RefreshTokenRequestDto request, string? ipAddress = null)
        {
            try
            {
                _logger.LogDebug("Token refresh attempt");

                var refreshToken = await _context.RefreshTokens
                    .Include(rt => rt.User)
                    .FirstOrDefaultAsync(rt => rt.Token == request.RefreshToken && rt.IsActive);

                if (refreshToken == null)
                {
                    _logger.LogWarning("Token refresh failed - Invalid or expired refresh token");
                    return ServiceResponseDto<AuthResponseDto>.ErrorResult("Invalid or expired refresh token");
                }

                // Check if user is still active
                if (!refreshToken.User.IsActive)
                {
                    _logger.LogWarning("Token refresh failed - User account is inactive: {UserId}", refreshToken.User.Id);
                    return ServiceResponseDto<AuthResponseDto>.ErrorResult("User account is inactive");
                }

                // Generate new tokens
                var accessToken = _jwtService.GenerateAccessToken(refreshToken.User);
                var newRefreshToken = _jwtService.GenerateRefreshToken();

                // Revoke old refresh token
                refreshToken.IsRevoked = true;
                refreshToken.RevokedAt = DateTime.UtcNow;
                refreshToken.RevokedByIp = ipAddress;
                refreshToken.ReplacedByToken = newRefreshToken;

                // Save new refresh token
                var newRefreshTokenEntity = new RefreshToken
                {
                    Token = newRefreshToken,
                    UserId = refreshToken.UserId,
                    ExpiresAt = DateTime.UtcNow.AddDays(7),
                    RevokedByIp = ipAddress
                };

                _context.RefreshTokens.Add(newRefreshTokenEntity);
                await _context.SaveChangesAsync();

                var authResponse = new AuthResponseDto
                {
                    Token = accessToken,
                    RefreshToken = newRefreshToken,
                    ExpiresAt = DateTime.UtcNow.AddHours(1),
                    User = _mapper.Map<UserDto>(refreshToken.User),
                    RequiresEmailVerification = !refreshToken.User.IsEmailVerified
                };

                _logger.LogInformation("Token refresh successful for user: {UserId}", refreshToken.User.Id);

                return ServiceResponseDto<AuthResponseDto>.SuccessResult(authResponse, "Token refreshed successfully");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error during token refresh");
                return ServiceResponseDto<AuthResponseDto>.ErrorResult("An error occurred during token refresh");
            }
        }

        public async Task<ServiceResponseDto<bool>> LogoutAsync(string refreshToken, string? ipAddress = null)
        {
            try
            {
                _logger.LogDebug("Logout attempt");

                var token = await _context.RefreshTokens
                    .FirstOrDefaultAsync(rt => rt.Token == refreshToken && rt.IsActive);

                if (token != null)
                {
                    token.IsRevoked = true;
                    token.RevokedAt = DateTime.UtcNow;
                    token.RevokedByIp = ipAddress;
                    await _context.SaveChangesAsync();

                    _logger.LogInformation("Logout successful for user: {UserId}", token.UserId);
                }

                return ServiceResponseDto<bool>.SuccessResult(true, "Logout successful");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error during logout");
                return ServiceResponseDto<bool>.ErrorResult("An error occurred during logout");
            }
        }

        public async Task<ServiceResponseDto<bool>> ForgotPasswordAsync(ForgotPasswordRequestDto request, string? ipAddress = null)
        {
            try
            {
                _logger.LogInformation("Forgot password request for email: {Email}", request.Email);

                var user = await _context.Users
                    .FirstOrDefaultAsync(u => u.Email == request.Email && u.IsActive);

                if (user == null)
                {
                    // For security, return success even if user doesn't exist
                    _logger.LogWarning("Forgot password request for non-existent email: {Email}", request.Email);
                    return ServiceResponseDto<bool>.SuccessResult(true, "If the email exists, a reset code has been sent");
                }

                // Check if can resend OTP
                if (!await _otpService.CanResendOtpAsync(user.Email, OtpTypes.PasswordReset))
                {
                    _logger.LogWarning("Forgot password request too frequent for email: {Email}", request.Email);
                    return ServiceResponseDto<bool>.ErrorResult("Please wait before requesting another reset code");
                }

                // Generate OTP
                var otp = await _otpService.GenerateOtpAsync(user.Id, user.Email, OtpTypes.PasswordReset, ipAddress);

                // Send OTP email
                await _emailService.SendOtpEmailAsync(user.Email, otp, user.UserName, "password reset");

                _logger.LogInformation("Password reset OTP sent for user: {UserId}", user.Id);

                return ServiceResponseDto<bool>.SuccessResult(true, "Reset code sent to your email");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error during forgot password for email: {Email}", request.Email);
                return ServiceResponseDto<bool>.ErrorResult("An error occurred while processing your request");
            }
        }

        public async Task<ServiceResponseDto<bool>> VerifyOtpAsync(VerifyOtpRequestDto request)
        {
            try
            {
                _logger.LogInformation("OTP verification attempt for email: {Email}", request.Email);

                var isValid = await _otpService.ValidateOtpAsync(request.Email, request.Otp, OtpTypes.EmailVerification);

                if (isValid)
                {
                    // Mark email as verified
                    var user = await _context.Users.FirstOrDefaultAsync(u => u.Email == request.Email);
                    if (user != null)
                    {
                        user.IsEmailVerified = true;
                        user.EmailVerifiedAt = DateTime.UtcNow;
                        await _context.SaveChangesAsync();

                        _logger.LogInformation("Email verification successful for user: {UserId}", user.Id);
                    }

                    return ServiceResponseDto<bool>.SuccessResult(true, "Email verified successfully");
                }

                _logger.LogWarning("OTP verification failed for email: {Email}", request.Email);
                return ServiceResponseDto<bool>.ErrorResult("Invalid or expired OTP");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error during OTP verification for email: {Email}", request.Email);
                return ServiceResponseDto<bool>.ErrorResult("An error occurred during OTP verification");
            }
        }

        public async Task<ServiceResponseDto<bool>> ResetPasswordAsync(ResetPasswordRequestDto request, string? ipAddress = null)
        {
            try
            {
                _logger.LogInformation("Password reset attempt for email: {Email}", request.Email);

                var isValidOtp = await _otpService.ValidateOtpAsync(request.Email, request.Otp, OtpTypes.PasswordReset);

                if (!isValidOtp)
                {
                    _logger.LogWarning("Password reset failed - Invalid OTP for email: {Email}", request.Email);
                    return ServiceResponseDto<bool>.ErrorResult("Invalid or expired reset code");
                }

                var user = await _context.Users.FirstOrDefaultAsync(u => u.Email == request.Email && u.IsActive);
                if (user == null)
                {
                    _logger.LogWarning("Password reset failed - User not found for email: {Email}", request.Email);
                    return ServiceResponseDto<bool>.ErrorResult("User not found");
                }

                // Update password
                user.PasswordHash = BCrypt.Net.BCrypt.HashPassword(request.NewPassword);
                user.UpdatedAt = DateTime.UtcNow;

                // Revoke all refresh tokens for security
                var refreshTokens = await _context.RefreshTokens
                    .Where(rt => rt.UserId == user.Id && rt.IsActive)
                    .ToListAsync();

                foreach (var token in refreshTokens)
                {
                    token.IsRevoked = true;
                    token.RevokedAt = DateTime.UtcNow;
                    token.RevokedByIp = ipAddress;
                }

                await _context.SaveChangesAsync();

                // Send confirmation email
                await _emailService.SendPasswordResetConfirmationAsync(user.Email, user.UserName);

                _logger.LogInformation("Password reset successful for user: {UserId}", user.Id);

                return ServiceResponseDto<bool>.SuccessResult(true, "Password reset successful");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error during password reset for email: {Email}", request.Email);
                return ServiceResponseDto<bool>.ErrorResult("An error occurred during password reset");
            }
        }

        public async Task<ServiceResponseDto<bool>> ChangePasswordAsync(int userId, ChangePasswordRequestDto request)
        {
            try
            {
                _logger.LogInformation("Change password attempt for user: {UserId}", userId);

                var user = await _context.Users.FirstOrDefaultAsync(u => u.Id == userId && u.IsActive);
                if (user == null)
                {
                    _logger.LogWarning("Change password failed - User not found: {UserId}", userId);
                    return ServiceResponseDto<bool>.ErrorResult("User not found");
                }

                // Verify current password
                if (!BCrypt.Net.BCrypt.Verify(request.CurrentPassword, user.PasswordHash))
                {
                    _logger.LogWarning("Change password failed - Invalid current password for user: {UserId}", userId);
                    return ServiceResponseDto<bool>.ErrorResult("Current password is incorrect");
                }

                // Update password
                user.PasswordHash = BCrypt.Net.BCrypt.HashPassword(request.NewPassword);
                user.UpdatedAt = DateTime.UtcNow;

                await _context.SaveChangesAsync();

                // Send notification email
                await _emailService.SendPasswordChangedNotificationAsync(user.Email, user.UserName);

                _logger.LogInformation("Password change successful for user: {UserId}", userId);

                return ServiceResponseDto<bool>.SuccessResult(true, "Password changed successfully");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error during password change for user: {UserId}", userId);
                return ServiceResponseDto<bool>.ErrorResult("An error occurred while changing password");
            }
        }

        public async Task<ServiceResponseDto<bool>> ResendOtpAsync(ResendOtpRequestDto request, string? ipAddress = null)
        {
            try
            {
                _logger.LogInformation("Resend OTP request for email: {Email}", request.Email);

                var user = await _context.Users.FirstOrDefaultAsync(u => u.Email == request.Email && u.IsActive);
                if (user == null)
                {
                    _logger.LogWarning("Resend OTP failed - User not found for email: {Email}", request.Email);
                    return ServiceResponseDto<bool>.ErrorResult("User not found");
                }

                // Determine OTP type
                var otpType = request.OtpType.ToLower() switch
                {
                    "passwordreset" => OtpTypes.PasswordReset,
                    "emailverification" => OtpTypes.EmailVerification,
                    _ => OtpTypes.EmailVerification
                };

                // Check if can resend
                if (!await _otpService.CanResendOtpAsync(user.Email, otpType))
                {
                    _logger.LogWarning("Resend OTP too frequent for email: {Email}, type: {Type}", request.Email, otpType);
                    return ServiceResponseDto<bool>.ErrorResult("Please wait before requesting another OTP");
                }

                // Generate new OTP
                var otp = await _otpService.GenerateOtpAsync(user.Id, user.Email, otpType, ipAddress);

                // Send OTP email
                var purpose = otpType == OtpTypes.PasswordReset ? "password reset" : "email verification";
                await _emailService.SendOtpEmailAsync(user.Email, otp, user.UserName, purpose);

                _logger.LogInformation("OTP resent successfully for user: {UserId}, type: {Type}", user.Id, otpType);

                return ServiceResponseDto<bool>.SuccessResult(true, "OTP sent successfully");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error during OTP resend for email: {Email}", request.Email);
                return ServiceResponseDto<bool>.ErrorResult("An error occurred while sending OTP");
            }
        }

        public async Task<ServiceResponseDto<UserDto>> GetUserProfileAsync(int userId)
        {
            try
            {
                _logger.LogDebug("Get profile request for user: {UserId}", userId);

                var user = await _context.Users
                    .FirstOrDefaultAsync(u => u.Id == userId && u.IsActive);

                if (user == null)
                {
                    _logger.LogWarning("Get profile failed - User not found: {UserId}", userId);
                    return ServiceResponseDto<UserDto>.ErrorResult("User not found");
                }

                var userDto = _mapper.Map<UserDto>(user);

                _logger.LogDebug("Profile retrieved successfully for user: {UserId}", userId);

                return ServiceResponseDto<UserDto>.SuccessResult(userDto, "Profile retrieved successfully");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error retrieving profile for user: {UserId}", userId);
                return ServiceResponseDto<UserDto>.ErrorResult("An error occurred while retrieving profile");
            }
        }
    }
}
