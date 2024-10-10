using Rey.Application.ViewModel;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Rey.Application.Interfaces
{
    public interface IPermissaoExternoAppService
    {
        PermissaoExternaViewModel CreateAndGet(PermissaoExternaViewModel permissaoExternaViewModel);
        bool DeleteById(long id);
        List<PermissaoExternaViewModel> GetAll();
        PermissaoExternaViewModel GetById(long id);
        List<PermissaoExternaViewModel> GetByPermissionName(string name);
        bool Update(PermissaoExternaViewModel permissaoExternaViewModel);
    }
}
