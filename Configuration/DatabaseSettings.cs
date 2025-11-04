namespace expenseTracker.Core.Configuration
{
    public class DatabaseSettings
    {
        public const string SectionName = "ConnectionStrings";
        public string DefaultConnection { get; set; } = string.Empty;
    }
}
