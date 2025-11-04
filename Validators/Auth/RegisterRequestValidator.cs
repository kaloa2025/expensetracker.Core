using expenseTracker.Shared.Constants;
using expenseTracker.Shared.DTOs.Auth;
using FluentValidation;

namespace expenseTracker.Core.Validators.Auth
{
    public class RegisterRequestValidator : AbstractValidator<RegisterRequestDto>
    {
        public RegisterRequestValidator()
        {
            RuleFor(x => x.Email)
                .NotEmpty().WithMessage(AppConstants.Validation.ErrorMessages.RequiredField)
                .MaximumLength(AppConstants.Validation.MaxEmailLength).WithMessage("Email is too long")
                .EmailAddress().WithMessage(AppConstants.Validation.ErrorMessages.InvalidEmail);

            RuleFor(x => x.Password)
                .NotEmpty().WithMessage(AppConstants.Validation.ErrorMessages.RequiredField)
                .MinimumLength(AppConstants.Validation.MinPasswordLength).WithMessage(AppConstants.Validation.ErrorMessages.InvalidPassword)
                .MaximumLength(AppConstants.Validation.MaxPasswordLength).WithMessage("Password is too long")
                .Must(BeAStrongPassword).WithMessage(AppConstants.Validation.ErrorMessages.WeakPassword);

            RuleFor(x => x.ConfirmPassword)
                .NotEmpty().WithMessage(AppConstants.Validation.ErrorMessages.RequiredField)
                .Equal(x => x.Password).WithMessage(AppConstants.Validation.ErrorMessages.PasswordMismatch);

            RuleFor(x => x.UserName)
                .NotEmpty().WithMessage(AppConstants.Validation.ErrorMessages.RequiredField)
                .MinimumLength(AppConstants.Validation.MinNameLength).WithMessage("Username is too short")
                .MaximumLength(AppConstants.Validation.MaxNameLength).WithMessage("Username is too long");

            RuleFor(x => x.AcceptTerms)
                .Equal(true).WithMessage("You must accept the terms and conditions");
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
