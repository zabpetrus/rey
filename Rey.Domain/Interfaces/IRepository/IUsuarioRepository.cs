using Rey.Domain.Entities;
using Rey.Domain.Entities.Auth;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Rey.Domain.Interfaces.IRepository
{
    public interface IUsuarioRepository
    {

        Task<Usuario> CreateAsync(Usuario novo);
        Task<bool> RegisterUserProfileAsync(long userId, long profileId);
        Task<Usuario> DeleteByIdAsync(long id);
        bool DeleteById(long id);
        Usuario? FindByCpf(string cpf);
        Task<Usuario> FindByCpfAsync(string cpf);
        Usuario? FindByEmail(string email);
        Task<Usuario> FindByEmailAsync(string email);
        Task<Usuario> FindByUsernameAsync(string username);
        List<Perfil> FetchUserProfilesByUserId(long userid);
        List<Usuario> GetAll();
        Task<Usuario> GetAllAsync();
        List<Perfil> GetPerfilByUser(Usuario usuarioExterno);
        Task<Usuario> GetByIdAsync(long id);
        Usuario GetById(long id);
        Task<Usuario> GetByResetPasswordTokenAsync(string token);
        List<Permissao> GetUserPermissionsByProfile(List<Perfil> list);
        Task<Usuario> VerifyAccountTokenAsync(string token);
        Task<RefreshToken> GeneratePasswordResetTokenAsync(Usuario usuarioExterno);
        bool Update(Usuario usuario);
        Task<bool> UpdateAsync(Usuario usuario);
    }
}
