using Rey.Domain.Entities;
using Rey.Domain.Entities.Auth;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Rey.Domain.Interfaces.IServices
{
    public interface IUsuarioExternoService
    {
        List<Perfil> FetchUserProfilesByUserId(long id);
        Task<Usuario> FindByUsernameAsync(string username);
        Usuario FindUserByCpf(string cpf);
        Task<Usuario> FindUserByCpfAsync(string username);
        Task<Usuario> FindUserByEmailAsync(string username);
        Task<Usuario> GetByIdAsync(long id);
        Usuario GetById(long id);
        bool Update(Usuario usuario);
        Task<bool> UpdateAsync(Usuario usuario); 
        bool DeleteById(long id);
        Task DeleteByIdAsync(long id);
        Task<Usuario> GetByResetPasswordTokenAsync(string token);
        Task<Usuario> CreateAsync(Usuario novo);
        List<Perfil> GetPerfilByUser(Usuario usuarioExterno);
        Task<Usuario> VerifyAccountTokenAsync(string token);
        Task<RefreshToken> GeneratePasswordResetTokenAsync(Usuario usuarioExterno);
        List<Usuario> GetAll();
        List<Permissao> GetUserPermissionsByProfileIds(List<long> list);
        List<Permissao> FetchUserPermissionByUserId(long id);
        Task<bool> RegistrarPerfil(long id1, long id2);
        Usuario? FindUserByEmail(string username);
        Usuario? FindByUsername(string username);
        Usuario GetByResetPasswordToken(string token);
        Usuario CreateAndGet(Usuario novo);
    }
}
