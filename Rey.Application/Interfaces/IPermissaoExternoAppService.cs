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
        object CreateAndGet(PermissaoExternaViewModel permissaoExternaViewModel);
        bool DeleteById(long id);
        object GetAll();
        object GetById(long id);
        object GetByPermissionName(string name);
        bool Update(PermissaoExternaViewModel permissaoExternaViewModel);
    }
}
