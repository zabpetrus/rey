using Rey.Application.ViewModel;
using Rey.Domain.Entities.Auth;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Rey.Application.Interfaces
{
    public interface IAuthAppService
    {
        Task<TokenViewModel> Login(LoginRequestViewModel request);
        Task<TokenViewModel> RefreshToken(RefreshTokenRequest request);
        Task<bool> ResetPassword(ResetPasswordViewModel model);
        Task Register(RegisterViewModel model);
        Task<bool> VerifyAccount(string token);
        Task<bool> ForgotPassword(ForgotPasswordViewModel model);
        Task<bool> Logout(LogoutViewModel model);
    }
}
