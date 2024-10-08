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
        List<PerfilExterno> FetchUserProfilesByUserId(long id);
        Task<UsuarioExterno> FindByUsernameAsync(string username);
        UsuarioExterno FindUserByCpf(string cpf);
        Task<UsuarioExterno> FindUserByCpfAsync(string username);
        Task<UsuarioExterno> FindUserByEmailAsync(string username);
        Task<UsuarioExterno> GetByIdAsync(long id);
        UsuarioExterno GetById(long id);
        bool Update(UsuarioExterno usuario);
        Task<bool> UpdateAsync(UsuarioExterno usuario); 
        bool DeleteById(long id);
        Task DeleteByIdAsync(long id);
        Task<UsuarioExterno> GetByResetPasswordTokenAsync(string token);
        Task<UsuarioExterno> CreateAsync(UsuarioExterno novo);
        List<PerfilExterno> GetPerfilByUser(UsuarioExterno usuarioExterno);
        Task<UsuarioExterno> VerifyAccountTokenAsync(string token);
        Task<RefreshToken> GeneratePasswordResetTokenAsync(UsuarioExterno usuarioExterno);
    }
}
