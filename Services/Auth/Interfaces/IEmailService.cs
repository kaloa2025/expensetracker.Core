namespace expenseTracker.Core.Services.Auth.Interfaces
{
    public interface IEmailService
    {
        Task<bool> SendWelcomeEmailAsync(string email, string firstName);
        Task<bool> SendOtpEmailAsync(string email, string otp, string firstName, string purpose = "verification");
        Task<bool> SendPasswordResetConfirmationAsync(string email, string firstName);
        Task<bool> SendPasswordChangedNotificationAsync(string email, string firstName);
        Task<bool> SendEmailVerificationAsync(string email, string firstName, string otp);
    }
}
