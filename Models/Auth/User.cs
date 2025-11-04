using expenseTracker.Core.Models.Common;
using System.ComponentModel.DataAnnotations;

namespace expenseTracker.Core.Models.Auth
{
    public class User : AuditableEntity
    {
        [Required]
        [EmailAddress]
        [MaxLength(255)]
        public string Email { get; set; } = string.Empty;

        [Required]
        public string PasswordHash { get; set; } = string.Empty;

        [Required]
        [MaxLength(100)]
        public string UserName { get; set; } = string.Empty;

        public bool IsEmailVerified { get; set; } = false;
        public DateTime? EmailVerifiedAt { get; set; }
        public DateTime? LastLoginAt { get; set; }
        public bool IsActive { get; set; } = true;
        public DateTime? DeactivatedAt { get; set; }

        // Navigation properties
        public ICollection<RefreshToken> RefreshTokens { get; set; } = new List<RefreshToken>();
        public ICollection<OtpToken> OtpTokens { get; set; } = new List<OtpToken>();
    }
}
