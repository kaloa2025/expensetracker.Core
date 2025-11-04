using expenseTracker.Core.Data;
using expenseTracker.Core.Models.Auth;
using expenseTracker.Core.Services.Auth.Interfaces;
using expenseTracker.Shared.Constants;
using expenseTracker.Shared.Enums;
using Microsoft.EntityFrameworkCore;
using System.Security.Cryptography;

namespace expenseTracker.Core.Services.Auth
{
    public class OtpService : IOtpService
    {
        private readonly CoreDbContext _context;
        private readonly ILogger<OtpService> _logger;

        public OtpService(CoreDbContext context, ILogger<OtpService> logger)
        {
            _context = context;
            _logger = logger;
        }

        public async Task<string> GenerateOtpAsync(int userId, string email, OtpTypes type, string? ipAddress = null)
        {
            try
            {
                // Invalidate existing OTPs of same type for this user
                await InvalidateOtpsAsync(userId, type);

                var otp = GenerateRandomOtp();
                var otpToken = new OtpToken
                {
                    UserId = userId,
                    Email = email,
                    Code = otp,
                    Type = type,
                    ExpiresAt = DateTime.UtcNow.AddMinutes(AppConstants.OtpSettings.OtpExpiryMinutes),
                    IpAddress = ipAddress
                };

                _context.OtpTokens.Add(otpToken);
                await _context.SaveChangesAsync();

                _logger.LogInformation("OTP generated for user {UserId}, type {Type}", userId, type);

                return otp;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error generating OTP for user {UserId}, type {Type}", userId, type);
                throw;
            }
        }

        public async Task<bool> ValidateOtpAsync(string email, string otp, OtpTypes type)
        {
            try
            {
                var otpToken = await _context.OtpTokens
                    .FirstOrDefaultAsync(ot =>
                        ot.Email == email &&
                        ot.Code == otp &&
                        ot.Type == type &&
                        !ot.IsUsed &&
                        ot.ExpiresAt > DateTime.UtcNow);

                if (otpToken == null)
                {
                    _logger.LogWarning("OTP validation failed: Invalid or expired OTP for email {Email}, type {Type}", email, type);
                    return false;
                }

                // Increment attempt count
                otpToken.AttemptCount++;

                // Check max attempts
                if (otpToken.AttemptCount > AppConstants.OtpSettings.MaxOtpAttempts)
                {
                    otpToken.IsUsed = true;
                    otpToken.UsedAt = DateTime.UtcNow;
                    await _context.SaveChangesAsync();

                    _logger.LogWarning("OTP validation failed: Maximum attempts exceeded for email {Email}, type {Type}", email, type);
                    return false;
                }

                // Mark as used if valid
                otpToken.IsUsed = true;
                otpToken.UsedAt = DateTime.UtcNow;
                await _context.SaveChangesAsync();

                _logger.LogInformation("OTP validation successful for email {Email}, type {Type}", email, type);
                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error validating OTP for email {Email}, type {Type}", email, type);
                return false;
            }
        }

        public async Task<bool> InvalidateOtpsAsync(int userId, OtpTypes type)
        {
            try
            {
                var existingOtps = await _context.OtpTokens
                    .Where(ot => ot.UserId == userId && ot.Type == type && !ot.IsUsed)
                    .ToListAsync();

                foreach (var otp in existingOtps)
                {
                    otp.IsUsed = true;
                    otp.UsedAt = DateTime.UtcNow;
                }

                await _context.SaveChangesAsync();

                _logger.LogDebug("Invalidated {Count} OTPs for user {UserId}, type {Type}", existingOtps.Count, userId, type);
                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error invalidating OTPs for user {UserId}, type {Type}", userId, type);
                return false;
            }
        }

        public async Task<bool> CanResendOtpAsync(string email, OtpTypes type)
        {
            try
            {
                var lastOtp = await _context.OtpTokens
                    .Where(ot => ot.Email == email && ot.Type == type)
                    .OrderByDescending(ot => ot.CreatedAt)
                    .FirstOrDefaultAsync();

                if (lastOtp == null)
                    return true;

                var cooldownPeriod = TimeSpan.FromMinutes(AppConstants.OtpSettings.OtpResendIntervalSeconds);
                var canResend = DateTime.UtcNow >= lastOtp.CreatedAt.Add(cooldownPeriod);

                _logger.LogDebug("OTP resend check for email {Email}, type {Type}: {CanResend}", email, type, canResend);

                return canResend;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error checking OTP resend eligibility for email {Email}, type {Type}", email, type);
                return false;
            }
        }

        public string GenerateRandomOtp()
        {
            try
            {
                using var rng = RandomNumberGenerator.Create();
                var bytes = new byte[4];
                rng.GetBytes(bytes);
                var randomNumber = BitConverter.ToUInt32(bytes, 0);
                var otp = (randomNumber % 1000000).ToString("D6");

                _logger.LogDebug("Random OTP generated");

                return otp;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error generating random OTP");
                throw;
            }
        }

        public async Task CleanupExpiredOtpsAsync()
        {
            try
            {
                var expiredOtps = await _context.OtpTokens
                    .Where(ot => ot.ExpiresAt <= DateTime.UtcNow || ot.IsUsed)
                    .Where(ot => ot.CreatedAt <= DateTime.UtcNow.AddHours(-24)) // Keep for 24 hours for audit
                    .ToListAsync();

                if (expiredOtps.Any())
                {
                    _context.OtpTokens.RemoveRange(expiredOtps);
                    await _context.SaveChangesAsync();

                    _logger.LogInformation("Cleaned up {Count} expired OTP tokens", expiredOtps.Count);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error during OTP cleanup");
            }
        }
    }
}