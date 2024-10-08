using Rey.Application.ViewModel;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Rey.Application.Interfaces
{
    public interface IUsuarioExternoAppService
    {
        UsuarioExternoViewModel FindUserByCpf(string cpf);
    }
}
