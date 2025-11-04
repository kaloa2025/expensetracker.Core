using expenseTracker.Core.Models.Common;
using System.ComponentModel.DataAnnotations;

namespace expenseTracker.Core.Models.Auth
{
    public class RefreshToken : AuditableEntity
    {

        [Required]
        [MaxLength(500)]
        public string Token { get; set; } = string.Empty;

        [Required]
        public DateTime ExpiresAt { get; set; }

        public bool IsRevoked { get; set; } = false;
        public DateTime? RevokedAt { get; set; }
        public string? RevokedByIp { get; set; }
        public string? ReplacedByToken { get; set; }

        // Foreign key
        public int UserId { get; set; }
        public User User { get; set; } = null!;

        // Computed properties
        public bool IsExpired => DateTime.UtcNow >= ExpiresAt;
        public bool IsActive => !IsRevoked && !IsExpired;
    }
}
