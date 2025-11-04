using expenseTracker.Shared.DTOs.Common;
using FluentValidation;
using Newtonsoft.Json;
using System.Net;

namespace expenseTracker.Core.Middleware
{
    public class ErrorHandlingMiddleware
    {
        private readonly RequestDelegate _next;
        private readonly ILogger<ErrorHandlingMiddleware> _logger;

        public ErrorHandlingMiddleware(RequestDelegate next, ILogger<ErrorHandlingMiddleware> logger)
        {
            _next = next;
            _logger = logger;
        }

        public async Task InvokeAsync(HttpContext context)
        {
            try
            {
                await _next(context);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Unhandled exception occurred");
                await HandleExceptionAsync(context, ex);
            }
        }

        private static async Task HandleExceptionAsync(HttpContext context, Exception exception)
        {
            context.Response.ContentType = "application/json";

            var response = exception switch
            {
                ValidationException validationEx => new
                {
                    StatusCode = (int)HttpStatusCode.BadRequest,
                    Response = ServiceResponseDto<object>.ValidationErrorResult(
                        validationEx.Errors.Select(e => e.ErrorMessage).ToList()
                    )
                },
                ArgumentException argumentEx => new
                {
                    StatusCode = (int)HttpStatusCode.BadRequest,
                    Response = ServiceResponseDto<object>.ErrorResult("Invalid request parameters", argumentEx.Message)
                },
                UnauthorizedAccessException => new
                {
                    StatusCode = (int)HttpStatusCode.Unauthorized,
                    Response = ServiceResponseDto<object>.ErrorResult("Unauthorized access")
                },
                KeyNotFoundException => new
                {
                    StatusCode = (int)HttpStatusCode.NotFound,
                    Response = ServiceResponseDto<object>.ErrorResult("Resource not found")
                },
                TimeoutException => new
                {
                    StatusCode = (int)HttpStatusCode.RequestTimeout,
                    Response = ServiceResponseDto<object>.ErrorResult("Request timeout")
                },
                _ => new
                {
                    StatusCode = (int)HttpStatusCode.InternalServerError,
                    Response = ServiceResponseDto<object>.ErrorResult("Internal server error")
                }
            };

            context.Response.StatusCode = response.StatusCode;

            var jsonResponse = JsonConvert.SerializeObject(response.Response, new JsonSerializerSettings
            {
                NullValueHandling = NullValueHandling.Ignore
            });

            await context.Response.WriteAsync(jsonResponse);
        }
    }
}
