using expenseTracker.Shared.Constants;
using expenseTracker.Shared.DTOs.Auth;
using FluentValidation;

namespace expenseTracker.Core.Validators.Auth
{
    public class ResetPasswordRequestValidator : AbstractValidator<ResetPasswordRequestDto>
    {
        public ResetPasswordRequestValidator()
        {
            RuleFor(x => x.Email)
                .NotEmpty().WithMessage(AppConstants.Validation.ErrorMessages.RequiredField)
                .EmailAddress().WithMessage(AppConstants.Validation.ErrorMessages.InvalidEmail);

            RuleFor(x => x.Otp)
                .NotEmpty().WithMessage(AppConstants.Validation.ErrorMessages.RequiredField)
                .Length(AppConstants.OtpSettings.OtpLength).WithMessage(AppConstants.Validation.ErrorMessages.InvalidOtp)
                .Must(BeAllDigits).WithMessage(AppConstants.Validation.ErrorMessages.InvalidOtp);

            RuleFor(x => x.NewPassword)
                .NotEmpty().WithMessage(AppConstants.Validation.ErrorMessages.RequiredField)
                .MinimumLength(AppConstants.Validation.MinPasswordLength).WithMessage(AppConstants.Validation.ErrorMessages.InvalidPassword)
                .MaximumLength(AppConstants.Validation.MaxPasswordLength).WithMessage("Password is too long")
                .Must(BeAStrongPassword).WithMessage(AppConstants.Validation.ErrorMessages.WeakPassword);

            RuleFor(x => x.ConfirmPassword)
                .NotEmpty().WithMessage(AppConstants.Validation.ErrorMessages.RequiredField)
                .Equal(x => x.NewPassword).WithMessage(AppConstants.Validation.ErrorMessages.PasswordMismatch);
        }

        private static bool BeAllDigits(string otp)
        {
            return !string.IsNullOrWhiteSpace(otp) && otp.All(char.IsDigit);
        }

        private static bool BeAStrongPassword(string password)
        {
            if (string.IsNullOrWhiteSpace(password))
                return false;

            bool hasUpper = password.Any(char.IsUpper);
            bool hasLower = password.Any(char.IsLower);
            bool hasDigit = password.Any(char.IsDigit);

            return hasUpper && hasLower && hasDigit;
        }
    }
}
