//using expenseTracker.Core.Models.Auth;
//using Microsoft.EntityFrameworkCore;
//using Microsoft.EntityFrameworkCore.Metadata.Builders;

//namespace expenseTracker.Core.Data.Configurations
//{
//    public class RefreshTokenConfiguration : IEntityTypeConfiguration<RefreshToken>
//    {
//        public void Configure(EntityTypeBuilder<RefreshToken> builder)
//        {
//            builder.ToTable("RefreshTokens");

//            builder.HasKey(rt => rt.Id);

//            builder.HasIndex(rt => rt.Token)
//                   .IsUnique()
//                   .HasDatabaseName("IX_RefreshTokens_Token");

//            builder.HasIndex(rt => rt.UserId)
//                   .HasDatabaseName("IX_RefreshTokens_UserId");

//            builder.Property(rt => rt.Token)
//                   .HasMaxLength(500)
//                   .IsRequired();

//            builder.Property(rt => rt.ExpiresAt)
//                   .IsRequired();

//            builder.Property(rt => rt.IsRevoked)
//                   .HasDefaultValue(false);

//            builder.Property(rt => rt.RevokedByIp)
//                   .HasMaxLength(50);

//            builder.Property(rt => rt.ReplacedByToken)
//                   .HasMaxLength(500);

//            builder.Property(rt => rt.CreatedAt)
//                   .HasDefaultValueSql("GETUTCDATE()");

//            builder.Property(rt => rt.UpdatedAt)
//                   .HasDefaultValueSql("GETUTCDATE()");

//            // Ignore computed properties
//            builder.Ignore(rt => rt.IsExpired);
//            builder.Ignore(rt => rt.IsActive);
//        }
//    }
//}
