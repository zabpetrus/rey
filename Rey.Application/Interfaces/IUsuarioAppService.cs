using Rey.Application.ViewModel;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Rey.Application.Interfaces
{
    public interface IUsuarioAppService
    {
        Task<UsuarioViewModel> CreateAndGetAsync(UsuarioViewModel usuarioExternoViewModel);
        Task<bool> CreateUserProfile(UsuarioPerfilViewModel request);
        Task<bool> DeleteById(long id);
        UsuarioViewModel FindUserByCpf(string cpf);
        Task<List<UsuarioViewModel>> GetAll();
        UsuarioViewModel GetById(long id);
        Task<bool> Update(UsuarioViewModel usuarioExternoViewModel);
    }
}
