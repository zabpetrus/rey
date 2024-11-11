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
        Permissao CreateAndGet(Permissao perfil);
        bool DeleteById(long id);
        List<Permissao> GetAll();
        Permissao GetById(long id);
        List<Permissao> GetByPermissionName(string name);
        bool Update(Permissao perfilExternoViewModel);
    }
}
