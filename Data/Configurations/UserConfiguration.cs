//using expenseTracker.Core.Models.Auth;
//using Microsoft.EntityFrameworkCore;
//using Microsoft.EntityFrameworkCore.Metadata.Builders;

//namespace expenseTracker.Core.Data.Configurations
//{
//    public class UserConfiguration: IEntityTypeConfiguration<User>
//    {
//        public void Configure(EntityTypeBuilder<User> builder)
//        {
//            builder.ToTable("Users");

//            builder.HasKey(u => u.Id);

//            builder.HasIndex(u => u.Email)
//                   .IsUnique()
//                   .HasDatabaseName("IX_Users_Email");

//            builder.Property(u => u.Email)
//                   .HasMaxLength(255)
//                   .IsRequired();

//            builder.Property(u => u.PasswordHash)
//                   .IsRequired();

//            builder.Property(u => u.UserName)
//                   .HasMaxLength(100)
//                   .IsRequired();

//            builder.Property(u => u.IsEmailVerified)
//                   .HasDefaultValue(false);

//            builder.Property(u => u.IsActive)
//                   .HasDefaultValue(true);

//            builder.Property(u => u.CreatedAt)
//                   .HasDefaultValueSql("GETUTCDATE()");

//            builder.Property(u => u.UpdatedAt)
//                   .HasDefaultValueSql("GETUTCDATE()");

//            // Relationships
//            builder.HasMany(u => u.RefreshTokens)
//                   .WithOne(rt => rt.User)
//                   .HasForeignKey(rt => rt.UserId)
//                   .OnDelete(DeleteBehavior.Cascade);

//            builder.HasMany(u => u.OtpTokens)
//                   .WithOne(ot => ot.User)
//                   .HasForeignKey(ot => ot.UserId)
//                   .OnDelete(DeleteBehavior.Cascade);
//        }
//    }
//}
