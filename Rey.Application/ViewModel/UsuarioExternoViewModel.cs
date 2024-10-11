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
        public string Senha { get; set; }
        public string Cpf { get; set; }
        public string Email { get; set; }
        public string Telefone { get; set; }
        public bool? Ativo { get; set; }
        public long Id { get; internal set; }
    }
}
