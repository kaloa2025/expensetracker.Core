using expenseTracker.Core.Models.Common;
using expenseTracker.Shared.Enums;
using System.ComponentModel.DataAnnotations;

namespace expenseTracker.Core.Models.Auth
{
    public class OtpToken : AuditableEntity
    {
        [Required]
        [MaxLength(255)]
        public string Email { get; set; } = string.Empty;

        [Required]
        [StringLength(6)]
        public string Code { get; set; } = string.Empty;

        [Required]
        public OtpTypes Type { get; set; }

        [Required]
        public DateTime ExpiresAt { get; set; }

        public bool IsUsed { get; set; } = false;
        public DateTime? UsedAt { get; set; }
        public int AttemptCount { get; set; } = 0;
        public string? IpAddress { get; set; }

        // Foreign key
        public int UserId { get; set; }
        public User User { get; set; } = null!;

        // Computed properties
        public bool IsExpired => DateTime.UtcNow >= ExpiresAt;
        public bool IsValid => !IsUsed && !IsExpired;
    }
}
