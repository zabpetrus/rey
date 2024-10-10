using Rey.Domain.Entities;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Rey.Domain.Interfaces.IRepository
{
    public interface IPermissaoExternoRepository
    {
        List<PermissaoExterno> RetrievePermissionsByProfile(PerfilExterno perfil);
        PermissaoExterno CreateAndGet(PermissaoExterno perfil);
        bool DeleteById(long id);
        List<PermissaoExterno> GetAll();
        PermissaoExterno GetById(long id);
        bool Update(PermissaoExterno perfilExternoViewModel);
        List<PermissaoExterno> GetByPermissionName(string name);
    }
}
