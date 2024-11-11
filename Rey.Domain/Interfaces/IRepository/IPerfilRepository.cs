using Rey.Domain.Entities;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Rey.Domain.Interfaces.IRepository
{
    public interface IPerfilRepository
    {
        Perfil CreateAndGet(Perfil perfil);
        bool DeleteById(long id);
        List<Perfil> GetAll();
        Perfil GetById(long id);
        bool Update(Perfil perfilExternoViewModel);


    }
}
