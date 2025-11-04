using System.Diagnostics;

namespace expenseTracker.Core.Middleware
{
    public class RequestLoggingMiddleware
    {
        private readonly RequestDelegate _next;
        private readonly ILogger<RequestLoggingMiddleware> _logger;

        public RequestLoggingMiddleware(RequestDelegate next, ILogger<RequestLoggingMiddleware> logger)
        {
            _next = next;
            _logger = logger;
        }

        public async Task InvokeAsync(HttpContext context)
        {
            var stopwatch = Stopwatch.StartNew();

            var correlationId = context.Request.Headers["X-Correlation-ID"].FirstOrDefault()
                               ?? Guid.NewGuid().ToString();

            context.Items["CorrelationId"] = correlationId;
            context.Response.Headers["X-Correlation-ID"] = correlationId;

            // Log request
            _logger.LogInformation("Request started: {Method} {Path} | Correlation ID: {CorrelationId} | IP: {IP}",
                context.Request.Method,
                context.Request.Path,
                correlationId,
                GetClientIpAddress(context));

            try
            {
                await _next(context);
            }
            finally
            {
                stopwatch.Stop();

                // Log response
                _logger.LogInformation("Request completed: {Method} {Path} | Status: {StatusCode} | Duration: {Duration}ms | Correlation ID: {CorrelationId}",
                    context.Request.Method,
                    context.Request.Path,
                    context.Response.StatusCode,
                    stopwatch.ElapsedMilliseconds,
                    correlationId);
            }
        }

        private static string? GetClientIpAddress(HttpContext context)
        {
            try
            {
                var forwardedFor = context.Request.Headers["X-Forwarded-For"].FirstOrDefault();
                if (!string.IsNullOrEmpty(forwardedFor))
                {
                    return forwardedFor.Split(',').FirstOrDefault()?.Trim();
                }

                var realIp = context.Request.Headers["X-Real-IP"].FirstOrDefault();
                if (!string.IsNullOrEmpty(realIp))
                {
                    return realIp;
                }

                return context.Connection.RemoteIpAddress?.ToString();
            }
            catch
            {
                return "Unknown";
            }
        }
    }
}
