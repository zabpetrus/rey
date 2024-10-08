using Rey.Application.ViewModel;
using Rey.Domain.Entities.Auth;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Rey.Application.Interfaces
{
    public interface IAuthenticatorService
    {
        RefreshToken RefreshToken(string accessToken, string refreshToken, string? username);
        public UsuarioExternoViewModel RevokeToken(string username);


    }
}
