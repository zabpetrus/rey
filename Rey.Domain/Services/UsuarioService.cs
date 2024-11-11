using Rey.Domain.Entities;
using Rey.Domain.Entities.Auth;
using Rey.Domain.Interfaces.IRepository;
using Rey.Domain.Interfaces.IServices;
using System.Threading.Tasks;

namespace Rey.Domain.Services
{
    public class UsuarioService : IUsuarioExternoService
    {
        private readonly IUsuarioRepository _usuarioExternoRepository;

        public UsuarioService(IUsuarioRepository usuarioExternoRepository)
        {
            _usuarioExternoRepository = usuarioExternoRepository;
        }

        public bool DeleteById(long id)
        {
            return _usuarioExternoRepository.DeleteById(id);
        }


        public Task<Usuario> CreateAsync(Usuario novo)
        {
            return _usuarioExternoRepository.CreateAsync(novo);
        }


        public Task DeleteByIdAsync(long id)
        {
            return _usuarioExternoRepository.DeleteByIdAsync(id);
        }

        public List<Perfil> FetchUserProfilesByUserId(long id)
        {
            return _usuarioExternoRepository.FetchUserProfilesByUserId(id); 
        }

        public Task<Usuario> FindByUsernameAsync(string username)
        {
            return _usuarioExternoRepository.FindByUsernameAsync(username);
        }

        public Usuario FindUserByCpf(string cpf)
        {
            return _usuarioExternoRepository.FindByCpf(cpf);
        }

        public Task<Usuario> FindUserByCpfAsync(string cpf)
        {
            return _usuarioExternoRepository.FindByCpfAsync(cpf);
        }

        public Task<Usuario> FindUserByEmailAsync(string email)
        {
            return _usuarioExternoRepository.FindByEmailAsync(email);
        }

        public Usuario GetById(long id)
        {
            return _usuarioExternoRepository.GetById(id);
        }

        public Task<Usuario> GetByIdAsync(long id)
        {
            return _usuarioExternoRepository.GetByIdAsync(id);
        }

        public bool Update(Usuario usuario)
        {
            return _usuarioExternoRepository.Update(usuario);   
        }

        public Task<bool> UpdateAsync(Usuario usuario)
        {
            return _usuarioExternoRepository.UpdateAsync(usuario);
        }

        //Obter USuario pelo reset token
        public Task<Usuario> GetByResetPasswordTokenAsync(string token)
        {
            return _usuarioExternoRepository.GetByResetPasswordTokenAsync(token);
        }

        //Obter os perfis por usuario
        public List<Perfil> GetPerfilByUser(Usuario usuarioExterno)
        {
            return _usuarioExternoRepository.GetPerfilByUser(usuarioExterno);   
        }

        public Task<Usuario> VerifyAccountTokenAsync(string token)
        {
            return _usuarioExternoRepository.VerifyAccountTokenAsync(token);
        }

        public Task<RefreshToken> GeneratePasswordResetTokenAsync(Usuario usuarioExterno)
        {
            return _usuarioExternoRepository.GeneratePasswordResetTokenAsync(usuarioExterno);   
        }

        public List<Usuario> GetAll()
        {
            return _usuarioExternoRepository.GetAll();
        }

        public List<Permissao> GetUserPermissionsByProfile(List<Perfil> list)
        {
            return _usuarioExternoRepository.GetUserPermissionsByProfile(list);
        }

        public List<Permissao> FetchUserPermissionByUserId(long userid)
        {
            throw new NotImplementedException();
        }

        public Task<bool> RegistrarPerfil(long id1, long id2)
        {
            throw new NotImplementedException();
        }

        public List<Permissao> GetUserPermissionsByProfileIds(List<long> list)
        {
            throw new NotImplementedException();
        }

        public Usuario? FindUserByEmail(string username)
        {
            throw new NotImplementedException();
        }

        public Usuario? FindByUsername(string username)
        {
            throw new NotImplementedException();
        }

        public Usuario GetByResetPasswordToken(string token)
        {
            throw new NotImplementedException();
        }

        public Usuario CreateAndGet(Usuario novo)
        {
            throw new NotImplementedException();
        }
    }
}
