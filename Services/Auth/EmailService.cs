using expenseTracker.Core.Configuration;
using expenseTracker.Core.Services.Auth.Interfaces;
using Microsoft.Extensions.Options;
using System.Net;
using System.Net.Mail;

namespace expenseTracker.Core.Services.Auth
{
    public class EmailService : IEmailService
    {
        private readonly EmailSettings _emailSettings;
        private readonly ILogger<EmailService> _logger;

        public EmailService(IOptions<EmailSettings> emailSettings, ILogger<EmailService> logger)
        {
            _emailSettings = emailSettings.Value;
            _logger = logger;
        }

        public async Task<bool> SendWelcomeEmailAsync(string email, string firstName)
        {
            try
            {
                var subject = "Welcome to ExpenseTracker!";
                var body = $@"
                <html>
                <body>
                    <h2>Welcome to ExpenseTracker, {firstName}!</h2>
                    <p>Thank you for joining us. Your account has been created successfully.</p>
                    <p>You can now start tracking your expenses and managing your finances.</p>
                    <p>Best regards,<br/>ExpenseTracker Team</p>
                </body>
                </html>";

                return await SendEmailAsync(email, subject, body);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error sending welcome email to {Email}", email);
                return false;
            }
        }

        public async Task<bool> SendOtpEmailAsync(string email, string otp, string firstName, string purpose = "verification")
        {
            try
            {
                var subject = $"Your {purpose} code - ExpenseTracker";
                var body = $@"
                <html>
                <body>
                    <h2>Hello {firstName},</h2>
                    <p>Your {purpose} code is: <strong>{otp}</strong></p>
                    <p>This code will expire in 10 minutes.</p>
                    <p>If you didn't request this code, please ignore this email.</p>
                    <p>Best regards,<br/>ExpenseTracker Team</p>
                </body>
                </html>";

                return await SendEmailAsync(email, subject, body);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error sending OTP email to {Email}", email);
                return false;
            }
        }

        public async Task<bool> SendPasswordResetConfirmationAsync(string email, string firstName)
        {
            try
            {
                var subject = "Password Reset Confirmation - ExpenseTracker";
                var body = $@"
                <html>
                <body>
                    <h2>Hello {firstName},</h2>
                    <p>Your password has been successfully reset.</p>
                    <p>If you didn't make this change, please contact our support team immediately.</p>
                    <p>Best regards,<br/>ExpenseTracker Team</p>
                </body>
                </html>";

                return await SendEmailAsync(email, subject, body);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error sending password reset confirmation email to {Email}", email);
                return false;
            }
        }

        public async Task<bool> SendPasswordChangedNotificationAsync(string email, string firstName)
        {
            try
            {
                var subject = "Password Changed - ExpenseTracker";
                var body = $@"
                <html>
                <body>
                    <h2>Hello {firstName},</h2>
                    <p>Your account password has been changed successfully.</p>
                    <p>If you didn't make this change, please contact our support team immediately.</p>
                    <p>Best regards,<br/>ExpenseTracker Team</p>
                </body>
                </html>";

                return await SendEmailAsync(email, subject, body);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error sending password changed notification email to {Email}", email);
                return false;
            }
        }

        public async Task<bool> SendEmailVerificationAsync(string email, string firstName, string otp)
        {
            try
            {
                var subject = "Verify Your Email - ExpenseTracker";
                var body = $@"
                <html>
                <body>
                    <h2>Hello {firstName},</h2>
                    <p>Please verify your email address to complete your registration.</p>
                    <p>Your verification code is: <strong>{otp}</strong></p>
                    <p>This code will expire in 10 minutes.</p>
                    <p>If you didn't create an account, please ignore this email.</p>
                    <p>Best regards,<br/>ExpenseTracker Team</p>
                </body>
                </html>";

                return await SendEmailAsync(email, subject, body);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error sending email verification to {Email}", email);
                return false;
            }
        }

        private async Task<bool> SendEmailAsync(string toEmail, string subject, string body)
        {
            try
            {
                // For development/testing, just log the email instead of sending
                if (string.IsNullOrEmpty(_emailSettings.Username) || string.IsNullOrEmpty(_emailSettings.Password))
                {
                    _logger.LogInformation("EMAIL SIMULATION - To: {Email}, Subject: {Subject}, Body: {Body}",
                        toEmail, subject, body);
                    return true;
                }

                using var client = new SmtpClient(_emailSettings.SmtpServer, _emailSettings.Port)
                {
                    UseDefaultCredentials = false,
                    Credentials = new NetworkCredential(_emailSettings.Username, _emailSettings.Password),
                    EnableSsl = _emailSettings.EnableSsl
                };

                var mailMessage = new MailMessage
                {
                    From = new MailAddress(_emailSettings.FromEmail, _emailSettings.FromName),
                    Subject = subject,
                    Body = body,
                    IsBodyHtml = true
                };

                mailMessage.To.Add(toEmail);

                await client.SendMailAsync(mailMessage);

                _logger.LogInformation("Email sent successfully to {Email}", toEmail);
                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to send email to {Email}", toEmail);
                return false;
            }
        }
    }
}
