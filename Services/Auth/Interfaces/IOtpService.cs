using expenseTracker.Shared.Enums;

namespace expenseTracker.Core.Services.Auth.Interfaces
{
    public interface IOtpService
    {
        Task<string> GenerateOtpAsync(int userId, string email, OtpTypes type, string? ipAddress = null);
        Task<bool> ValidateOtpAsync(string email, string otp, OtpTypes type);
        Task<bool> InvalidateOtpsAsync(int userId, OtpTypes type);
        Task<bool> CanResendOtpAsync(string email, OtpTypes type);
        string GenerateRandomOtp();
        Task CleanupExpiredOtpsAsync();
    }
}
