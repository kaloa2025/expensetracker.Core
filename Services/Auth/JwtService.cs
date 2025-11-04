using expenseTracker.Core.Configuration;
using expenseTracker.Core.Models.Auth;
using expenseTracker.Core.Services.Auth.Interfaces;
using expenseTracker.Shared.Constants;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace expenseTracker.Core.Services.Auth
{
    public class JwtService : IJwtService
    {
        private readonly JwtSettings _jwtSettings;
        private readonly ILogger<JwtService> _logger;

        public JwtService(IOptions<JwtSettings> jwtSettings, ILogger<JwtService> logger)
        {
            _jwtSettings = jwtSettings.Value;
            _logger = logger;
        }

        public string GenerateAccessToken(User user)
        {
            try
            {
                var claims = new[]
                {
                new Claim(AppConstants.JwtClaimUserId, user.Id.ToString()),
                new Claim(AppConstants.JwtClaimEmail, user.Email),
                new Claim(AppConstants.JwtClaimUserName, user.UserName),
                new Claim(AppConstants.JwtClaimIsEmailVerified, user.IsEmailVerified.ToString()),
                new Claim(JwtRegisteredClaimNames.Sub, user.Id.ToString()),
                new Claim(JwtRegisteredClaimNames.Email, user.Email),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new Claim(JwtRegisteredClaimNames.Iat, DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString(), ClaimValueTypes.Integer64)
            };

                var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwtSettings.SecretKey));
                var credentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

                var token = new JwtSecurityToken(
                    issuer: _jwtSettings.Issuer,
                    audience: _jwtSettings.Audience,
                    claims: claims,
                    expires: DateTime.UtcNow.AddMinutes(_jwtSettings.AccessTokenExpiryMinutes),
                    signingCredentials: credentials
                );

                var tokenString = new JwtSecurityTokenHandler().WriteToken(token);

                _logger.LogDebug("Access token generated for user {UserId}", user.Id);

                return tokenString;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error generating access token for user {UserId}", user.Id);
                throw;
            }
        }

        public string GenerateRefreshToken()
        {
            try
            {
                var randomBytes = new byte[32];
                using var rng = RandomNumberGenerator.Create();
                rng.GetBytes(randomBytes);
                var refreshToken = Convert.ToBase64String(randomBytes);

                _logger.LogDebug("Refresh token generated");

                return refreshToken;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error generating refresh token");
                throw;
            }
        }

        public ClaimsPrincipal? ValidateToken(string token)
        {
            try
            {
                var tokenHandler = new JwtSecurityTokenHandler();
                var key = Encoding.UTF8.GetBytes(_jwtSettings.SecretKey);

                var validationParameters = new TokenValidationParameters
                {
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = new SymmetricSecurityKey(key),
                    ValidateIssuer = true,
                    ValidIssuer = _jwtSettings.Issuer,
                    ValidateAudience = true,
                    ValidAudience = _jwtSettings.Audience,
                    ValidateLifetime = true,
                    ClockSkew = TimeSpan.Zero
                };

                var principal = tokenHandler.ValidateToken(token, validationParameters, out _);

                _logger.LogDebug("Token validation successful");

                return principal;
            }
            catch (SecurityTokenExpiredException)
            {
                _logger.LogWarning("Token validation failed: Token expired");
                return null;
            }
            catch (SecurityTokenException ex)
            {
                _logger.LogWarning(ex, "Token validation failed: {Message}", ex.Message);
                return null;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Unexpected error during token validation");
                return null;
            }
        }

        public int? GetUserIdFromToken(string token)
        {
            try
            {
                var principal = ValidateToken(token);
                var userIdClaim = principal?.FindFirst(AppConstants.JwtClaimUserId)?.Value;
                return int.TryParse(userIdClaim, out var userId) ? userId : null;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error extracting user ID from token");
                return null;
            }
        }

        public string? GetEmailFromToken(string token)
        {
            try
            {
                var principal = ValidateToken(token);
                return principal?.FindFirst(AppConstants.JwtClaimEmail)?.Value;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error extracting email from token");
                return null;
            }
        }

        public bool IsTokenExpired(string token)
        {
            try
            {
                var tokenHandler = new JwtSecurityTokenHandler();
                var jwt = tokenHandler.ReadJwtToken(token);
                return jwt.ValidTo <= DateTime.UtcNow;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error checking token expiry");
                return true;
            }
        }
    }
}
