using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Rey.Application.ViewModel
{
    public class PerfilExternoViewModel
    {
        public long Id {  get; set; }

        public string Codigo { get; set; }

        public string Descricao { get; set; }

        public bool Ativo { get; set; } = true;
    }
}
