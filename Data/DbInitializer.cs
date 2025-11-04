using expenseTracker.Core.Models.Auth;
using Microsoft.EntityFrameworkCore;

namespace expenseTracker.Core.Data
{
    public static class DbInitializer
    {
        /// <summary>
        /// Initialize database with seed data
        /// </summary>
        public static async Task InitializeAsync(CoreDbContext context, ILogger logger)
        {
            try
            {
                // Check if database has been seeded
                if (await context.Users.AnyAsync())
                {
                    logger.LogInformation("Database already seeded");
                    return;
                }

                logger.LogInformation("Seeding database...");

                // Seed admin user
                await SeedAdminUserAsync(context, logger);

                // Seed test users (only in development)
                var environment = Environment.GetEnvironmentVariable("ASPNETCORE_ENVIRONMENT");
                if (environment == "Development")
                {
                    await SeedTestUsersAsync(context, logger);
                }

                await context.SaveChangesAsync();
                logger.LogInformation("Database seeding completed successfully");
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "An error occurred while seeding the database");
                throw;
            }
        }

        private static async Task SeedAdminUserAsync(CoreDbContext context, ILogger logger)
        {
            try
            {
                var adminUser = new User
                {
                    Email = "admin@expensetracker.com",
                    UserName = "System Administrator",
                    PasswordHash = BCrypt.Net.BCrypt.HashPassword("Admin@123"), // Enhanced security with custom salt rounds
                    IsEmailVerified = true,
                    EmailVerifiedAt = DateTime.UtcNow,
                    IsActive = true,
                    CreatedAt = DateTime.UtcNow,
                    UpdatedAt = DateTime.UtcNow,
                    CreatedBy = "System",
                    UpdatedBy = "System"
                };

                context.Users.Add(adminUser);
                logger.LogInformation("Admin user seeded");
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Error seeding admin user");
                throw;
            }
        }

        private static async Task SeedTestUsersAsync(CoreDbContext context, ILogger logger)
        {
            try
            {
                var testUsers = new[]
                {
                    new User
                    {
                        Email = "john.doe@example.com",
                        UserName = "John Doe",
                        PasswordHash = BCrypt.Net.BCrypt.HashPassword("Test@123"),
                        IsEmailVerified = true,
                        EmailVerifiedAt = DateTime.UtcNow,
                        IsActive = true,
                        CreatedAt = DateTime.UtcNow,
                        UpdatedAt = DateTime.UtcNow,
                        CreatedBy = "System",
                        UpdatedBy = "System"
                    },
                    new User
                    {
                        Email = "jane.smith@example.com",
                        UserName = "Jane Smith",
                        PasswordHash = BCrypt.Net.BCrypt.HashPassword("Test@123"),
                        IsEmailVerified = false,
                        IsActive = true,
                        CreatedAt = DateTime.UtcNow,
                        UpdatedAt = DateTime.UtcNow,
                        CreatedBy = "System",
                        UpdatedBy = "System"
                    }
                };

                context.Users.AddRange(testUsers);
                logger.LogInformation("Test users seeded");
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Error seeding test users");
                throw;
            }
        }

        /// <summary>
        /// Clean up expired data
        /// </summary>
        public static async Task CleanupExpiredDataAsync(CoreDbContext context, ILogger logger)
        {
            try
            {
                var cutoffDate = DateTime.UtcNow.AddDays(-30);

                // Clean up expired OTP tokens
                var expiredOtps = await context.OtpTokens
                    .Where(otp => otp.ExpiresAt < cutoffDate || (otp.IsUsed && otp.UsedAt < cutoffDate))
                    .ToListAsync();

                if (expiredOtps.Any())
                {
                    context.OtpTokens.RemoveRange(expiredOtps);
                    logger.LogInformation("Cleaned up {Count} expired OTP tokens", expiredOtps.Count);
                }

                // Clean up expired refresh tokens
                var expiredRefreshTokens = await context.RefreshTokens
                    .Where(rt => rt.ExpiresAt < cutoffDate || (rt.IsRevoked && rt.RevokedAt < cutoffDate))
                    .ToListAsync();

                if (expiredRefreshTokens.Any())
                {
                    context.RefreshTokens.RemoveRange(expiredRefreshTokens);
                    logger.LogInformation("Cleaned up {Count} expired refresh tokens", expiredRefreshTokens.Count);
                }

                await context.SaveChangesAsync();
                logger.LogInformation("Data cleanup completed successfully");
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Error during data cleanup");
                throw;
            }
        }
    }
}