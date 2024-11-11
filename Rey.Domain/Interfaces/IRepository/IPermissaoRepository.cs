using Rey.Domain.Entities;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Rey.Domain.Interfaces.IRepository
{
    public interface IPermissaoRepository
    {
        List<Permissao> RetrievePermissionsByProfile(Perfil perfil);
        Permissao CreateAndGet(Permissao perfil);
        bool DeleteById(long id);
        List<Permissao> GetAll();
        Permissao GetById(long id);
        bool Update(Permissao perfilExternoViewModel);
        List<Permissao> GetByPermissionName(string name);


    }
}
