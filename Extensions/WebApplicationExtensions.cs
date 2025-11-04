using expenseTracker.Core.Data;
using expenseTracker.Core.Middleware;
using expenseTracker.Core.Services.Auth.Interfaces;
using Microsoft.EntityFrameworkCore;
using Microsoft.OpenApi.Models;  // Added for Swagger
using Microsoft.AspNetCore.Diagnostics.HealthChecks;  // Added for health checks

namespace expenseTracker.Core.Extensions
{
    public static class WebApplicationExtensions
    {
        /// <summary>
        /// Configure the HTTP request pipeline
        /// </summary>
        public static WebApplication ConfigurePipeline(this WebApplication app)
        {
            // Configure for development environment
            if (app.Environment.IsDevelopment())
            {
                app.UseSwagger();
                app.UseSwaggerUI(c =>
                {
                    c.SwaggerEndpoint("/swagger/v1/swagger.json", "ExpenseTracker Core API V1");
                    c.RoutePrefix = string.Empty; // Set Swagger UI at root
                });
            }

            // Security headers
            app.UseSecurityHeaders();

            // HTTPS redirection
            app.UseHttpsRedirection();

            // Custom middleware
            app.UseMiddleware<RequestLoggingMiddleware>();
            app.UseMiddleware<ErrorHandlingMiddleware>();

            // CORS
            app.UseCors("DefaultCorsPolicy");

            // Authentication & Authorization
            app.UseAuthentication();
            app.UseAuthorization();

            // Map controllers
            app.MapControllers();

            // Health checks
            app.MapHealthChecks("/health");

            return app;
        }

        /// <summary>
        /// Initialize database and seed data
        /// </summary>
        public static async Task<WebApplication> InitializeDatabaseAsync(this WebApplication app)
        {
            using var scope = app.Services.CreateScope();
            var services = scope.ServiceProvider;
            var logger = services.GetRequiredService<ILogger<Program>>();

            try
            {
                var context = services.GetRequiredService<CoreDbContext>();

                // Ensure database is created and migrations are applied
                await context.Database.MigrateAsync();

                // Initialize database with seed data
                await DbInitializer.InitializeAsync(context, logger);

                logger.LogInformation("Database initialized successfully");
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "An error occurred while initializing the database");
                throw;
            }

            return app;
        }

        /// <summary>
        /// Start background services
        /// </summary>
        public static WebApplication StartBackgroundServices(this WebApplication app)
        {
            // Start OTP cleanup service
            _ = Task.Run(async () =>
            {
                using var scope = app.Services.CreateScope();
                var otpService = scope.ServiceProvider.GetRequiredService<IOtpService>();
                var logger = scope.ServiceProvider.GetRequiredService<ILogger<Program>>();

                while (!app.Lifetime.ApplicationStopping.IsCancellationRequested)
                {
                    try
                    {
                        await otpService.CleanupExpiredOtpsAsync();
                        logger.LogDebug("OTP cleanup completed");
                    }
                    catch (Exception ex)
                    {
                        logger.LogError(ex, "Error during OTP cleanup");
                    }

                    // Run cleanup every hour
                    await Task.Delay(TimeSpan.FromHours(1), app.Lifetime.ApplicationStopping);
                }
            });

            return app;
        }

        /// <summary>
        /// Add security headers
        /// </summary>
        private static IApplicationBuilder UseSecurityHeaders(this IApplicationBuilder app)
        {
            app.Use(async (context, next) =>
            {
                // Add security headers
                context.Response.Headers.Add("X-Content-Type-Options", "nosniff");
                context.Response.Headers.Add("X-Frame-Options", "DENY");
                context.Response.Headers.Add("X-XSS-Protection", "1; mode=block");
                context.Response.Headers.Add("Referrer-Policy", "strict-origin-when-cross-origin");

                // Remove server header
                context.Response.Headers.Remove("Server");

                await next();
            });

            return app;
        }
    }
}