using expenseTracker.Shared.DTOs.Auth;
using expenseTracker.Shared.DTOs.Common;

namespace expenseTracker.Core.Services.Auth.Interfaces
{
    public interface IAuthService
    {
        Task<ServiceResponseDto<AuthResponseDto>> LoginAsync(LoginRequestDto request, string? ipAddress = null);
        Task<ServiceResponseDto<AuthResponseDto>> RegisterAsync(RegisterRequestDto request, string? ipAddress = null);
        Task<ServiceResponseDto<AuthResponseDto>> RefreshTokenAsync(RefreshTokenRequestDto request, string? ipAddress = null);
        Task<ServiceResponseDto<bool>> LogoutAsync(string refreshToken, string? ipAddress = null);
        Task<ServiceResponseDto<bool>> ForgotPasswordAsync(ForgotPasswordRequestDto request, string? ipAddress = null);
        Task<ServiceResponseDto<bool>> VerifyOtpAsync(VerifyOtpRequestDto request);
        Task<ServiceResponseDto<bool>> ResetPasswordAsync(ResetPasswordRequestDto request, string? ipAddress = null);
        Task<ServiceResponseDto<bool>> ChangePasswordAsync(int userId, ChangePasswordRequestDto request);
        Task<ServiceResponseDto<bool>> ResendOtpAsync(ResendOtpRequestDto request, string? ipAddress = null);
        Task<ServiceResponseDto<UserDto>> GetUserProfileAsync(int userId);
    }
}
