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
        public UsuarioExterno? FindByEmail(string email);

        public UsuarioExterno? FindByCpf(string cpf);
        Task<UsuarioExterno> FindByUsernameAsync(string username);
        Task<UsuarioExterno> FindByCpfAsync(string cpf);
        Task<UsuarioExterno> FindByEmailAsync(string email);
        List<PerfilExterno> FetchUserProfilesByUserId(long id);
        UsuarioExterno GetById(long id);
        Task<UsuarioExterno> GetByIdAsync(long id);
        bool Update(UsuarioExterno usuario);
        Task<bool> UpdateAsync(UsuarioExterno usuario);
        Task DeleteByIdAsync(long id);
        bool DeleteById(long id);
        Task<UsuarioExterno> CreateAsync(UsuarioExterno novo);
        Task<UsuarioExterno> GetByResetPasswordTokenAsync(string token);
        List<PerfilExterno> GetPerfilByUser(UsuarioExterno usuarioExterno);
        Task<UsuarioExterno> VerifyAccountTokenAsync(string token);
        Task<RefreshToken> GeneratePasswordResetTokenAsync(UsuarioExterno usuarioExterno);
    }
}
