using expenseTracker.Shared.Constants;
using expenseTracker.Shared.DTOs.Auth;
using FluentValidation;

namespace expenseTracker.Core.Validators.Auth
{
    public class LoginRequestValidator : AbstractValidator<LoginRequestDto>
    {
        public LoginRequestValidator()
        {
            RuleFor(x => x.Email)
                .NotEmpty().WithMessage(AppConstants.Validation.ErrorMessages.RequiredField)
                .MaximumLength(AppConstants.Validation.MaxEmailLength).WithMessage("Email is too long")
                .EmailAddress().WithMessage(AppConstants.Validation.ErrorMessages.InvalidEmail);

            RuleFor(x => x.Password)
                .NotEmpty().WithMessage(AppConstants.Validation.ErrorMessages.RequiredField)
                .MinimumLength(AppConstants.Validation.MinPasswordLength).WithMessage(AppConstants.Validation.ErrorMessages.InvalidPassword)
                .MaximumLength(AppConstants.Validation.MaxPasswordLength).WithMessage("Password is too long");
        }
    }
}
