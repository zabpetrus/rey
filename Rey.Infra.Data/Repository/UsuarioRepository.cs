using Rey.Domain.Entities;
using Rey.Domain.Interfaces.IRepository;
using Rey.Infra.Data.Context;
using Microsoft.EntityFrameworkCore;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Rey.Domain.Entities.Auth;
using Rey.Domain.Entities._Abstract;

namespace Rey.Infra.Data.Repository
{
    public class UsuarioRepository : IUsuarioRepository
    {
        private readonly ApplicationDbContext _applicationDbContext;

        public UsuarioRepository(ApplicationDbContext applicationDbContext)
        {
            _applicationDbContext = applicationDbContext;
        }

        // Métodos Find já implementados
        public Usuario? FindByEmail(string email)
        {
            return _applicationDbContext.UsuariosExternos.FirstOrDefault(e => e.Email == email);
        }

        public Usuario? FindByCpf(string cpf)
        {
            return _applicationDbContext.UsuariosExternos.FirstOrDefault(e => e.Cpf == cpf);
        }

        public async Task<Usuario?> FindByUsernameAsync(string username)
        {
            return await _applicationDbContext.UsuariosExternos.FirstOrDefaultAsync(e => e.Nome == username);
        }

        public async Task<Usuario?> FindByCpfAsync(string cpf)
        {
            return await _applicationDbContext.UsuariosExternos.FirstOrDefaultAsync(e => e.Cpf == cpf);
        }

        public async Task<Usuario?> FindByEmailAsync(string email)
        {
            return await _applicationDbContext.UsuariosExternos.FirstOrDefaultAsync(e => e.Email == email);
        }

        // Método para buscar perfis por ID do usuário
        public List<Domain.Entities.Perfil> FetchUserProfilesByUserId(long id)
        {
            var perfilIds = _applicationDbContext.UsuariosPerfisExternos
                .Where(up => up.UsuarioId == id)
                .Select(up => up.PerfilId)
                .ToList();

            var perfis = _applicationDbContext.PerfisExternos
                .Where(p => perfilIds.Contains(p.Id))
                .ToList();

            return perfis;
        }

        // Busca usuário por ID
        public Usuario GetById(long id)
        {
            return _applicationDbContext.UsuariosExternos.Find(id);
        }

        // Busca assíncrona por ID
        public async Task<Usuario?> GetByIdAsync(long id)
        {
            return await _applicationDbContext.UsuariosExternos.FindAsync(id);
        }

        // Atualização síncrona
        public bool Update(Usuario usuario)
        {
            _applicationDbContext.UsuariosExternos.Update(usuario);
            return _applicationDbContext.SaveChanges() > 0;
        }

        // Atualização assíncrona
        public async Task<bool> UpdateAsync(Usuario usuario)
        {
            _applicationDbContext.UsuariosExternos.Update(usuario);
            return await _applicationDbContext.SaveChangesAsync() > 0;
        }

        // Deleção assíncrona por ID
        public async Task DeleteByIdAsync(long id)
        {
            var usuario = await _applicationDbContext.UsuariosExternos.FindAsync(id);
            if (usuario != null)
            {
                _applicationDbContext.UsuariosExternos.Remove(usuario);
                await _applicationDbContext.SaveChangesAsync();
            }
        }

        // Deleção síncrona por ID
        public bool DeleteById(long id)
        {
            var usuario = _applicationDbContext.UsuariosExternos.Find(id);
            if (usuario != null)
            {
                _applicationDbContext.UsuariosExternos.Remove(usuario);
                return _applicationDbContext.SaveChanges() > 0;
            }
            return false;
        }

        // Criação assíncrona de um novo usuário externo
        public async Task<Usuario> CreateAsync(Usuario novo)
        {
            await _applicationDbContext.UsuariosExternos.AddAsync(novo);
            await _applicationDbContext.SaveChangesAsync();
            return novo;
        }

        // Busca assíncrona por token de redefinição de senha
        public async Task<Usuario?> GetByResetPasswordTokenAsync(string token)
        {

            // Verifica se o token foi fornecido
            if (string.IsNullOrEmpty(token))
            {
                throw new ArgumentException("O token não pode ser nulo ou vazio.", nameof(token));
            }

            // Busca no banco de dados o RefreshToken associado ao token
            var refreshToken = await _applicationDbContext.Set<RefreshToken>()
                .Where(rt => rt.ResetPasswordTokenExpiration == token && rt.IsActive)
                .FirstOrDefaultAsync();

            // Se não encontrar o token ou o token estiver expirado, retorna null
            if (refreshToken == null || refreshToken.IsExpired)
            {
                return null;
            }

            // Encontra o usuário associado ao RefreshToken
            var usuario = await _applicationDbContext.Set<Usuario>()
                .Where(u => u.Id == refreshToken.UsuarioId)
                .FirstOrDefaultAsync();

            // Retorna o usuário encontrado ou null
            return usuario;
        }

        public List<Domain.Entities.Perfil> GetPerfilByUser(Usuario usuarioExterno)
        {
            // Verifica se o usuário é nulo
            if (usuarioExterno == null)
                throw new ArgumentNullException(nameof(usuarioExterno));

            // Obtém os Perfis associados ao usuário a partir da tabela de junção UsuariosPerfisExternos
            var perfilIds = _applicationDbContext.UsuariosPerfisExternos
                .Where(up => up.UsuarioId == usuarioExterno.Id) // Filtra os perfis pelo usuário
                .Select(up => up.PerfilId) // Seleciona os IDs dos perfis
                .ToList(); // Converte para uma lista

            // Busca os PerfisExternos usando os IDs coletados
            var perfis = _applicationDbContext.PerfisExternos
                .Where(p => perfilIds.Contains(p.Id)) // Filtra perfis com base nos IDs
                .ToList(); // Converte para uma lista e retorna

            return perfis; // Retorna a lista de PerfisExternos
        }

        public async Task<Usuario?> VerifyAccountTokenAsync(string token)
        {
            var refreshToken = await _applicationDbContext.RefreshTokens
                .FirstOrDefaultAsync(e => e.Token == token);

            if (refreshToken != null)
            {
                return await _applicationDbContext.UsuariosExternos
                    .FirstOrDefaultAsync(e => e.Id == refreshToken.UsuarioId);
            }

            return null; // Token não encontrado
        }

        public async Task<RefreshToken> GeneratePasswordResetTokenAsync(Usuario usuarioExterno)
        {
            // Verifica se o usuário é nulo
            if (usuarioExterno == null)
                throw new ArgumentNullException(nameof(usuarioExterno));

            // Cria um novo token de redefinição de senha
            var token = new RefreshToken
            {
                UsuarioId = usuarioExterno.Id,
                Token = Guid.NewGuid().ToString(), // Gera um novo token
                Expires = DateTime.UtcNow.AddHours(1), // Define a expiração do token
                Created = DateTime.UtcNow,
                CreatedByIp =  null //Pensar melhor - vou reestruturar isso
            };

            // Adiciona o token no contexto
            await _applicationDbContext.RefreshTokens.AddAsync(token);
            await _applicationDbContext.SaveChangesAsync(); // Salva as alterações no banco

            return token; // Retorna o token gerado
        }

        public Task<bool> RegisterUserProfileAsync(long userId, long profileId)
        {
            throw new NotImplementedException();
        }

        Task<Usuario> IUsuarioRepository.DeleteByIdAsync(long id)
        {
            throw new NotImplementedException();
        }

        public List<Usuario> GetAll()
        {
            throw new NotImplementedException();
        }

        public Task<Usuario> GetAllAsync()
        {
            throw new NotImplementedException();
        }

        public List<Domain.Entities.Permissao> GetUserPermissionsByProfile(List<Domain.Entities.Perfil> list)
        {
            throw new NotImplementedException();
        }
    }
}
