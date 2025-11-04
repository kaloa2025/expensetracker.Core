using expenseTracker.Core.Models.Auth;
using System.Security.Claims;

namespace expenseTracker.Core.Services.Auth.Interfaces
{
    public interface IJwtService
    {
        string GenerateAccessToken(User user);
        string GenerateRefreshToken();
        ClaimsPrincipal? ValidateToken(string token);
        int? GetUserIdFromToken(string token);
        string? GetEmailFromToken(string token);
        bool IsTokenExpired(string token);
    }
}
