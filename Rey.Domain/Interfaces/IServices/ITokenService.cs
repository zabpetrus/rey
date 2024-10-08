using Rey.Domain.Entities.Auth;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace Rey.Domain.Interfaces.IServices
{
    public interface ITokenService
    {
        public Token GerarTokenJwtByClaims(List<Claim> claims);
        public string GenerateRefreshToken();
        public ClaimsPrincipal GetPrincipalFromExpiredToken(string token);
        Task<Token> Login(string username, string senha);
        Task<Token> RefreshToken(string token, string ipadress);
        Task<bool> ResetPassword(string token, string novasenha);
        Task<UsuarioExterno> Register(Registration registration);
        Task<bool> RevokeTokens(string token);
    }
}
