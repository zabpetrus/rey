using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Rey.Application.ViewModel
{
    public class UsuarioExternoViewModel
    {
        public long Id { get; set; }
        public string NomeDeUsuario { get; set; }
        public string HashSenha { get; set; }
        public string Email { get; set; }
        public string Cpf { get; set; }
        public string RefreshToken { get; set; }
        public DateTime RefreshTokenExpiryTime { get; set; }
    }
}
