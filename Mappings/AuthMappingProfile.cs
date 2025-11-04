using AutoMapper;
using expenseTracker.Core.Models.Auth;
using expenseTracker.Shared.DTOs.Auth;

namespace expenseTracker.Core.Mappings
{
    public class AuthMappingProfile : Profile
    {
        public AuthMappingProfile()
        {
            // User mappings
            CreateMap<User, UserDto>()
                .ForMember(dest => dest.UserName, opt => opt.MapFrom(src => $"{src.UserName}"));

            // RegisterRequest to User mapping
            CreateMap<RegisterRequestDto, User>()
                .ForMember(dest => dest.PasswordHash, opt => opt.Ignore())
                .ForMember(dest => dest.IsEmailVerified, opt => opt.MapFrom(src => false))
                .ForMember(dest => dest.IsActive, opt => opt.MapFrom(src => true));

            // Additional mappings can be added here as needed
            CreateMap<User, AuthResponseDto>()
                .ForMember(dest => dest.Token, opt => opt.Ignore())
                .ForMember(dest => dest.RefreshToken, opt => opt.Ignore())
                .ForMember(dest => dest.ExpiresAt, opt => opt.Ignore())
                .ForMember(dest => dest.User, opt => opt.MapFrom(src => src))
                .ForMember(dest => dest.RequiresEmailVerification, opt => opt.MapFrom(src => !src.IsEmailVerified));
        }
    }
}
