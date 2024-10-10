using Rey.Application.ViewModel;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Rey.Application.Interfaces
{
    public interface IPerfilExternoAppService
    {
        PerfilExternoViewModel CreateAndGet(PerfilExternoViewModel perfilExternoViewModel);
        bool DeleteById(long id);
        List<PerfilExternoViewModel> GetAll();
        PerfilExternoViewModel GetById(long id);
        bool Update(PerfilExternoViewModel perfilExternoViewModel);
    }
}
