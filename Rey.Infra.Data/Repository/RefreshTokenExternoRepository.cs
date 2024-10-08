using Microsoft.EntityFrameworkCore;
using Rey.Domain.Entities.Auth;
using Rey.Domain.Interfaces.IRepository;
using Rey.Infra.Data.Context;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Rey.Infra.Data.Repository
{
    public class RefreshTokenExternoRepository : IRefreshTokenExternoRepository
    {
        private readonly ApplicationDbContext _context;

        public RefreshTokenExternoRepository(ApplicationDbContext context)
        {
            _context = context;
        }

        // Método para criar um novo refresh token
        public RefreshToken Create(RefreshToken refreshToken)
        {
            var existingTokens = _context.RefreshTokens
                .Where(t => t.UsuarioId == refreshToken.UsuarioId && t.IsActive)
                .ToList();

            foreach (var token in existingTokens)
            {
                token.Revoked = DateTime.UtcNow; // Marca como revogado
                token.RevokedByIp = refreshToken.CreatedByIp; // Opcional
                _context.RefreshTokens.Update(token); // Atualiza o token no banco
            }

            _context.RefreshTokens.Add(refreshToken);
            _context.SaveChanges();

            return refreshToken;
        }

        public async Task<RefreshToken> CreateAsync(RefreshToken refreshToken)
        {
            var existingTokens = await _context.RefreshTokens
                .Where(t => t.UsuarioId == refreshToken.UsuarioId && t.IsActive)
                .ToListAsync();

            foreach (var token in existingTokens)
            {
                token.Revoked = DateTime.UtcNow; // Marca como revogado
                token.RevokedByIp = refreshToken.CreatedByIp;
                _context.RefreshTokens.Update(token);
            }

            await _context.RefreshTokens.AddAsync(refreshToken);
            await _context.SaveChangesAsync();

            return refreshToken;
        }

        // Método para buscar um refresh token pelo valor do token
        public async Task<RefreshToken> GetByTokenAsync(string token)
        {
            return await _context.RefreshTokens.FirstOrDefaultAsync(t => t.Token == token);
        }

        // Método para buscar todos os refresh tokens de um usuário
        public async Task<List<RefreshToken>> GetByUserIdAsync(long userId)
        {
            return await _context.RefreshTokens
                .Where(t => t.UsuarioId == userId)
                .ToListAsync();
        }

        // Método para atualizar um refresh token
        public async Task<RefreshToken> UpdateAsync(RefreshToken refreshToken)
        {
            var existingToken = await _context.RefreshTokens
                .FirstOrDefaultAsync(t => t.Id == refreshToken.Id);

            if (existingToken != null)
            {
                existingToken.Token = refreshToken.Token;
                existingToken.Expires = refreshToken.Expires;
                existingToken.CreatedByIp = refreshToken.CreatedByIp;

                _context.RefreshTokens.Update(existingToken);
                await _context.SaveChangesAsync();

                return existingToken;
            }

            return null; // Token não encontrado
        }

        // Método para revogar um refresh token
        public async Task<bool> RevokeAsync(string token, string revokedByIp)
        {
            var refreshToken = await _context.RefreshTokens
                .FirstOrDefaultAsync(t => t.Token == token && t.IsActive);

            if (refreshToken != null)
            {
                refreshToken.Revoked = DateTime.UtcNow;
                refreshToken.RevokedByIp = revokedByIp;

                _context.RefreshTokens.Update(refreshToken);
                await _context.SaveChangesAsync();

                return true; // Token revogado com sucesso
            }

            return false; // Token não encontrado ou já revogado
        }

        // Método para deletar um refresh token
        public async Task<bool> DeleteAsync(long id)
        {
            var refreshToken = await _context.RefreshTokens.FindAsync(id);

            if (refreshToken != null)
            {
                _context.RefreshTokens.Remove(refreshToken);
                await _context.SaveChangesAsync();

                return true; // Token deletado com sucesso
            }

            return false; // Token não encontrado
        }

        // Método para buscar refresh tokens por UsuarioId
        public async Task<List<RefreshToken>> GetRefreshTokenByUsuarioIdAsync(long userId)
        {
            return await _context.RefreshTokens
                .Where(t => t.UsuarioId == userId)
                .ToListAsync();
        }

        // Método para deletar um refresh token por ID
        public async Task DeleteById(long id)
        {
            var refreshToken = await _context.RefreshTokens.FindAsync(id);

            if (refreshToken != null)
            {
                _context.RefreshTokens.Remove(refreshToken);
                await _context.SaveChangesAsync();
            }
        }

        // Método para buscar um refresh token pelo valor do token
        public async Task<RefreshToken> GetRefreshTokenAsync(string token)
        {
            return await _context.RefreshTokens
                .FirstOrDefaultAsync(t => t.Token == token);
        }

        // Método para remover um refresh token
        public async Task<bool> RemoveRefreshTokenAsync(RefreshToken refreshToken)
        {
            var existingToken = await _context.RefreshTokens.FindAsync(refreshToken.Id);

            if (existingToken != null)
            {
                _context.RefreshTokens.Remove(existingToken);
                await _context.SaveChangesAsync();
                return true; // Token removido com sucesso
            }

            return false; // Token não encontrado
        }
    }
}
