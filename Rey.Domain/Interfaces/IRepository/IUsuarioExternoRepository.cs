using Rey.Domain.Entities;
using Rey.Domain.Entities.Auth;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Rey.Domain.Interfaces.IRepository
{
    public interface IUsuarioExternoRepository
    {

        Task<UsuarioExterno> CreateAsync(UsuarioExterno novo);
        Task<bool> RegisterUserProfileAsync(long userId, long profileId);
        Task<UsuarioExterno> DeleteByIdAsync(long id);
        bool DeleteById(long id);
        UsuarioExterno? FindByCpf(string cpf);
        Task<UsuarioExterno> FindByCpfAsync(string cpf);
        UsuarioExterno? FindByEmail(string email);
        Task<UsuarioExterno> FindByEmailAsync(string email);
        Task<UsuarioExterno> FindByUsernameAsync(string username);
        List<PerfilExterno> FetchUserProfilesByUserId(long userid);
        List<UsuarioExterno> GetAll();
        Task<UsuarioExterno> GetAllAsync();
        List<PerfilExterno> GetPerfilByUser(UsuarioExterno usuarioExterno);
        Task<UsuarioExterno> GetByIdAsync(long id);
        UsuarioExterno GetById(long id);
        Task<UsuarioExterno> GetByResetPasswordTokenAsync(string token);
        List<PermissaoExterno> GetUserPermissionsByProfile(List<PerfilExterno> list);
        Task<UsuarioExterno> VerifyAccountTokenAsync(string token);
        Task<RefreshToken> GeneratePasswordResetTokenAsync(UsuarioExterno usuarioExterno);
        bool Update(UsuarioExterno usuario);
        Task<bool> UpdateAsync(UsuarioExterno usuario);
    }
}
