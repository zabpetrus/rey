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
        UsuarioExternoViewModel CreateAndGet(UsuarioExternoViewModel permissaoExternaViewModel);
        bool DeleteById(long id);
        UsuarioExternoViewModel FindUserByCpf(string cpf);
        List<UsuarioExternoViewModel> GetAll();
        List<UsuarioExternoViewModel> GetById(long id);
        bool Update(UsuarioExternoViewModel permissaoExternaViewModel);
    }
}
