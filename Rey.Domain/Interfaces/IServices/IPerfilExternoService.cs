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
        PerfilExterno CreateAndGet(PerfilExterno perfil);
        bool DeleteById(long id);
        List<PerfilExterno> GetAll();
        PerfilExterno GetById(long id);
        Task<PerfilExterno> GetByIdAsync(long perfilId);
        bool Update(PerfilExterno perfilExternoViewModel);
    }
}
