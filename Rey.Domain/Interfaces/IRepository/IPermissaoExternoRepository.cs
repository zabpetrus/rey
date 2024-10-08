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
    }
}
