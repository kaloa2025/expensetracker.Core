using expenseTracker.Shared.Models;

namespace expenseTracker.Core.Models.Common
{
    public abstract class AuditableEntity : BaseEntity
    {
        public string? CreatedBy { get; set; }
        public string? UpdatedBy { get; set; }
    }
}
