using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Rey.Application.ViewModel
{
    public class UsuarioExternoViewModel
    {
        public string Nome { get; set; }
        public string Senha { get; private set; }
        public string Cpf { get; set; }
        public string Email { get; set; }
        public string Telefone { get; set; }
        public string Sal { get; private set; }
        public string SenhaHash { get; private set; }
        public bool? Ativo { get; set; }
        public long Id { get; internal set; }
    }
}
