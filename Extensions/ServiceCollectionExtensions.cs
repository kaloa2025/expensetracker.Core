using expenseTracker.Core.Configuration;
using expenseTracker.Core.Data;
using expenseTracker.Core.Mappings;
using expenseTracker.Core.Services.Auth;
using expenseTracker.Core.Services.Auth.Interfaces;
using expenseTracker.Core.Validators.Auth;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.EntityFrameworkCore; // Added for DbContext
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using FluentValidation; // Added for FluentValidation
using FluentValidation.AspNetCore; // Added for FluentValidation ASP.NET Core extensions

namespace expenseTracker.Core.Extensions
{
    public static class ServiceCollectionExtensions
    {
        /// <summary>
        /// Add database configuration
        /// </summary>
        public static IServiceCollection AddDatabase(this IServiceCollection services, IConfiguration configuration)
        {
            var connectionString = configuration.GetConnectionString("DefaultConnection")
                ?? throw new InvalidOperationException("Database connection string is not configured");

            services.AddDbContext<CoreDbContext>(options =>
            {
                options.UseSqlServer(connectionString, sqlOptions =>
                {
                    sqlOptions.EnableRetryOnFailure(
                        maxRetryCount: 3,
                        maxRetryDelay: TimeSpan.FromSeconds(30),
                        errorNumbersToAdd: null);
                });

                // Enable sensitive data logging in development
                if (configuration.GetValue<bool>("Logging:EnableSensitiveDataLogging"))
                {
                    options.EnableSensitiveDataLogging();
                }
            });

            return services;
        }

        /// <summary>
        /// Add application services
        /// </summary>
        public static IServiceCollection AddApplicationServices(this IServiceCollection services, IConfiguration configuration)
        {
            // Configuration options
            services.Configure<JwtSettings>(configuration.GetSection(JwtSettings.SectionName));
            services.Configure<EmailSettings>(configuration.GetSection(EmailSettings.SectionName));

            // Application services
            services.AddScoped<IAuthService, AuthService>();
            services.AddScoped<IJwtService, JwtService>();
            services.AddScoped<IOtpService, OtpService>();
            services.AddScoped<IEmailService, EmailService>();

            return services;
        }

        /// <summary>
        /// Add AutoMapper configuration
        /// </summary>
        public static IServiceCollection AddAutoMapperConfig(this IServiceCollection services)
        {
            // Fixed: Use the correct overload
            services.AddAutoMapper(typeof(AuthMappingProfile).Assembly);
            return services;
        }

        /// <summary>
        /// Add FluentValidation configuration
        /// </summary>
        public static IServiceCollection AddValidationConfig(this IServiceCollection services)
        {
            // Fixed: Use the correct FluentValidation methods
            services.AddValidatorsFromAssemblyContaining<LoginRequestValidator>();
            services.AddFluentValidationAutoValidation();
            services.AddFluentValidationClientsideAdapters();

            return services;
        }

        /// <summary>
        /// Add JWT authentication
        /// </summary>
        public static IServiceCollection AddJwtAuthentication(this IServiceCollection services, IConfiguration configuration)
        {
            var jwtSettings = configuration.GetSection(JwtSettings.SectionName).Get<JwtSettings>()
                ?? throw new InvalidOperationException("JWT settings are not configured");

            if (string.IsNullOrEmpty(jwtSettings.SecretKey))
            {
                throw new InvalidOperationException("JWT SecretKey is not configured");
            }

            services.AddAuthentication(options =>
            {
                options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
                options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
            })
            .AddJwtBearer(options =>
            {
                options.TokenValidationParameters = new TokenValidationParameters
                {
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtSettings.SecretKey)),
                    ValidateIssuer = true,
                    ValidIssuer = jwtSettings.Issuer,
                    ValidateAudience = true,
                    ValidAudience = jwtSettings.Audience,
                    ValidateLifetime = true,
                    ClockSkew = TimeSpan.Zero
                };

                options.Events = new JwtBearerEvents
                {
                    OnChallenge = context =>
                    {
                        context.Response.StatusCode = 401;
                        context.Response.ContentType = "application/json";

                        var response = new { message = "Authentication required" };
                        return context.Response.WriteAsync(System.Text.Json.JsonSerializer.Serialize(response));
                    }
                };
            });

            return services;
        }

        /// <summary>
        /// Add CORS configuration
        /// </summary>
        public static IServiceCollection AddCorsConfig(this IServiceCollection services, IConfiguration configuration)
        {
            var allowedOrigins = configuration.GetSection("Cors:AllowedOrigins").Get<string[]>()
                ?? new[] { "https://localhost:7000" };

            services.AddCors(options =>
            {
                options.AddPolicy("DefaultCorsPolicy", policy =>
                {
                    policy.WithOrigins(allowedOrigins)
                          .AllowAnyMethod()
                          .AllowAnyHeader()
                          .AllowCredentials();
                });
            });

            return services;
        }

        /// <summary>
        /// Add Swagger/OpenAPI configuration
        /// </summary>
        public static IServiceCollection AddSwaggerConfig(this IServiceCollection services)
        {
            services.AddEndpointsApiExplorer();
            services.AddSwaggerGen(c =>
            {
                c.SwaggerDoc("v1", new Microsoft.OpenApi.Models.OpenApiInfo
                {
                    Title = "ExpenseTracker Core API",
                    Version = "v1",
                    Description = "API for ExpenseTracker application"
                });

                // Add JWT authentication to Swagger
                c.AddSecurityDefinition("Bearer", new Microsoft.OpenApi.Models.OpenApiSecurityScheme
                {
                    Description = "JWT Authorization header using the Bearer scheme",
                    Name = "Authorization",
                    In = Microsoft.OpenApi.Models.ParameterLocation.Header,
                    Type = Microsoft.OpenApi.Models.SecuritySchemeType.ApiKey,
                    Scheme = "Bearer"
                });

                c.AddSecurityRequirement(new Microsoft.OpenApi.Models.OpenApiSecurityRequirement
                {
                    {
                        new Microsoft.OpenApi.Models.OpenApiSecurityScheme
                        {
                            Reference = new Microsoft.OpenApi.Models.OpenApiReference
                            {
                                Type = Microsoft.OpenApi.Models.ReferenceType.SecurityScheme,
                                Id = "Bearer"
                            }
                        },
                        Array.Empty<string>()
                    }
                });
            });

            return services;
        }
    }
}