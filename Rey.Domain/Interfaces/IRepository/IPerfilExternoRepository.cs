using Rey.Domain.Entities;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Rey.Domain.Interfaces.IRepository
{
    public interface IPerfilExternoRepository
    {
        PerfilExterno CreateAndGet(PerfilExterno perfil);
        bool DeleteById(long id);
        List<PerfilExterno> GetAll();
        PerfilExterno GetById(long id);
        bool Update(PerfilExterno perfilExternoViewModel);
    }
}
