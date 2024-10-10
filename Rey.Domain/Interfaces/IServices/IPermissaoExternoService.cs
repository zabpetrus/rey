using Rey.Domain.Entities;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Rey.Domain.Interfaces.IServices
{
    public interface IPermissaoExternoService
    {
        PermissaoExterno CreateAndGet(PermissaoExterno perfil);
        bool DeleteById(long id);
        List<PermissaoExterno> GetAll();
        PermissaoExterno GetById(long id);
        List<PermissaoExterno> GetByPermissionName(string name);
        bool Update(PermissaoExterno perfilExternoViewModel);
    }
}
