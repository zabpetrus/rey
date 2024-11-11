using Rey.Domain.Entities;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Rey.Domain.Interfaces.IServices
{
    public interface IPerfilExternoService
    {
        Perfil CreateAndGet(Perfil perfil);
        bool DeleteById(long id);
        List<Perfil> GetAll();
        Perfil GetById(long id);
        Task<Perfil> GetByIdAsync(long perfilId);
        bool Update(Perfil perfilExternoViewModel);
    }
}
