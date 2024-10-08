using Rey.Domain.Entities;
using Rey.Domain.Entities.Auth;
using Rey.Domain.Interfaces.IRepository;
using Rey.Domain.Interfaces.IServices;
using System.Threading.Tasks;

namespace Rey.Domain.Services
{
    public class UsuarioExternoService : IUsuarioExternoService
    {
        private readonly IUsuarioExternoRepository _usuarioExternoRepository;

        public UsuarioExternoService(IUsuarioExternoRepository usuarioExternoRepository)
        {
            _usuarioExternoRepository = usuarioExternoRepository;
        }

        public bool DeleteById(long id)
        {
            return _usuarioExternoRepository.DeleteById(id);
        }


        public Task<UsuarioExterno> CreateAsync(UsuarioExterno novo)
        {
            return _usuarioExternoRepository.CreateAsync(novo);
        }


        public Task DeleteByIdAsync(long id)
        {
            return _usuarioExternoRepository.DeleteByIdAsync(id);
        }

        public List<PerfilExterno> FetchUserProfilesByUserId(long id)
        {
            return _usuarioExternoRepository.FetchUserProfilesByUserId(id); 
        }

        public Task<UsuarioExterno> FindByUsernameAsync(string username)
        {
            return _usuarioExternoRepository.FindByUsernameAsync(username);
        }

        public UsuarioExterno FindUserByCpf(string cpf)
        {
            return _usuarioExternoRepository.FindByCpf(cpf);
        }

        public Task<UsuarioExterno> FindUserByCpfAsync(string cpf)
        {
            return _usuarioExternoRepository.FindByCpfAsync(cpf);
        }

        public Task<UsuarioExterno> FindUserByEmailAsync(string email)
        {
            return _usuarioExternoRepository.FindByEmailAsync(email);
        }

        public UsuarioExterno GetById(long id)
        {
            return _usuarioExternoRepository.GetById(id);
        }

        public Task<UsuarioExterno> GetByIdAsync(long id)
        {
            return _usuarioExternoRepository.GetByIdAsync(id);
        }

        public bool Update(UsuarioExterno usuario)
        {
            return _usuarioExternoRepository.Update(usuario);   
        }

        public Task<bool> UpdateAsync(UsuarioExterno usuario)
        {
            return _usuarioExternoRepository.UpdateAsync(usuario);
        }

        //Obter USuario pelo reset token
        public Task<UsuarioExterno> GetByResetPasswordTokenAsync(string token)
        {
            return _usuarioExternoRepository.GetByResetPasswordTokenAsync(token);
        }

        //Obter os perfis por usuario
        public List<PerfilExterno> GetPerfilByUser(UsuarioExterno usuarioExterno)
        {
            return _usuarioExternoRepository.GetPerfilByUser(usuarioExterno);   
        }

        public Task<UsuarioExterno> VerifyAccountTokenAsync(string token)
        {
            return _usuarioExternoRepository.VerifyAccountTokenAsync(token);
        }

        public Task<RefreshToken> GeneratePasswordResetTokenAsync(UsuarioExterno usuarioExterno)
        {
            return _usuarioExternoRepository.GeneratePasswordResetTokenAsync(usuarioExterno);   
        }
    }
}
