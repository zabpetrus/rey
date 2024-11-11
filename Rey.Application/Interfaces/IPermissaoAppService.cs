using Rey.Application.ViewModel;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Rey.Application.Interfaces
{
    public interface IPermissaoAppService
    {
        PermissaoViewModel CreateAndGet(PermissaoViewModel permissaoExternaViewModel);
        bool DeleteById(long id);
        List<PermissaoViewModel> GetAll();
        PermissaoViewModel GetById(long id);
        List<PermissaoViewModel> GetByPermissionName(string name);
        bool Update(PermissaoViewModel permissaoExternaViewModel);
    }
}
