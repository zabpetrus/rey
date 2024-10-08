using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Rey.Application.ViewModel
{
    public class RegisterViewModel
    {
        public long Id { get; set; }
        public string NomeDeUsuario { get; set; }
        public string HashSenha { get; set; }
        public string Email { get; set; }
        public string Cpf { get; set; }
        public string RefreshToken { get; set; }
        public DateTime RefreshTokenExpiryTime { get; set; }
        public string RefreshTokenReset { get; internal set; }
        public string ResetPasswordTokenExpiration { get; internal set; }
    }
}
