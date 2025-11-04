using expenseTracker.Core.Extensions;
using Serilog;

var builder = WebApplication.CreateBuilder(args);

// Configure Serilog
Log.Logger = new LoggerConfiguration()
    .ReadFrom.Configuration(builder.Configuration)
    .Enrich.FromLogContext()
    .WriteTo.Console()
    .WriteTo.File("logs/log-.txt", rollingInterval: RollingInterval.Day)
    .CreateLogger();

builder.Host.UseSerilog();

try
{
    // Add services to the container
    builder.Services.AddDatabase(builder.Configuration);
    builder.Services.AddApplicationServices(builder.Configuration);
    builder.Services.AddAutoMapperConfig();
    builder.Services.AddValidationConfig();
    builder.Services.AddJwtAuthentication(builder.Configuration);
    builder.Services.AddCorsConfig(builder.Configuration);
    builder.Services.AddSwaggerConfig(); // Add this line
    builder.Services.AddHealthChecksConfig(builder.Configuration); // Add this line

    var app = builder.Build();

    // Configure the HTTP request pipeline
    app.ConfigurePipeline();

    // Initialize database - this might be causing the issue
    await app.InitializeDatabaseAsync();

    // Start background services
    app.StartBackgroundServices();

    Log.Information("Starting ExpenseTracker Core API");

    await app.RunAsync();
}
catch (Exception ex)
{
    Log.Fatal(ex, "Application terminated unexpectedly");
}
finally
{
    Log.CloseAndFlush();
}