//using expenseTracker.Core.Models.Auth;
//using Microsoft.EntityFrameworkCore;
//using Microsoft.EntityFrameworkCore.Metadata.Builders;

//namespace expenseTracker.Core.Data.Configurations
//{
//    public class OtpTokenConfiguration : IEntityTypeConfiguration<OtpToken>
//    {
//        public void Configure(EntityTypeBuilder<OtpToken> builder)
//        {
//            builder.ToTable("OtpTokens");

//            builder.HasKey(ot => ot.Id);

//            builder.HasIndex(ot => new { ot.Email, ot.Code, ot.Type })
//                   .HasDatabaseName("IX_OtpTokens_Email_Code_Type");

//            builder.HasIndex(ot => ot.UserId)
//                   .HasDatabaseName("IX_OtpTokens_UserId");

//            builder.Property(ot => ot.Email)
//                   .HasMaxLength(255)
//                   .IsRequired();

//            builder.Property(ot => ot.Code)
//                   .HasMaxLength(6)
//                   .IsRequired();

//            builder.Property(ot => ot.Type)
//                   .HasConversion<int>()
//                   .IsRequired();

//            builder.Property(ot => ot.ExpiresAt)
//                   .IsRequired();

//            builder.Property(ot => ot.IsUsed)
//                   .HasDefaultValue(false);

//            builder.Property(ot => ot.AttemptCount)
//                   .HasDefaultValue(0);

//            builder.Property(ot => ot.IpAddress)
//                   .HasMaxLength(50);

//            builder.Property(ot => ot.CreatedAt)
//                   .HasDefaultValueSql("GETUTCDATE()");

//            builder.Property(ot => ot.UpdatedAt)
//                   .HasDefaultValueSql("GETUTCDATE()");

//            // Ignore computed properties
//            builder.Ignore(ot => ot.IsExpired);
//            builder.Ignore(ot => ot.IsValid);
//        }
//    }
//}
