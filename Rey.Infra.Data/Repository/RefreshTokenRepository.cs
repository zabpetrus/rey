using Microsoft.EntityFrameworkCore;
using Rey.Domain.Entities.Auth;
using Rey.Domain.Interfaces.IRepository;
using Rey.Infra.Data.Context;
using System;
using System.Collections.Generic;
using System.Linq;

namespace Rey.Infra.Data.Repository
{
    public class RefreshTokenRepository : IRefreshTokenRepository
    {
        private readonly ApplicationDbContext _context;

        public RefreshTokenRepository(ApplicationDbContext context)
        {
            _context = context;
        }

        public RefreshToken Create(RefreshToken refreshToken)
        {
            // Obtém tokens existentes que não foram revogados e que ainda não expiraram
            var existingTokens = _context.RefreshTokens
                .Where(t => t.UsuarioId == refreshToken.UsuarioId).ToList();

            // Marca os tokens existentes como revogados
            foreach (var token in existingTokens)
            {
                token.Revoked = DateTime.UtcNow; // Marca como revogado
                token.RevokedByIp = refreshToken.CreatedByIp; // Opcional
                _context.RefreshTokens.Update(token); // Atualiza o token no banco
            }

            // Adiciona o novo token de refresh
            _context.RefreshTokens.Add(refreshToken);
            _context.SaveChanges();

            return refreshToken;
        }

        public RefreshToken CreateRefreshToken(string token)
        {
            var refreshToken = new RefreshToken
            {
                Token = token,
                Created = DateTime.UtcNow,
                Expires = DateTime.UtcNow.AddDays(7)
            };

            _context.Set<RefreshToken>().Add(refreshToken);
            _context.SaveChanges();

            return refreshToken;
        }

        public bool DeleteById(long id)
        {
            // Busca o refresh token
            var refreshToken = _context.RefreshTokens.Find(id);

            if (refreshToken != null)
            {
                _context.RefreshTokens.Remove(refreshToken); // Remove o token
                _context.SaveChanges(); // Salva as alterações
                return true; // Token deletado com sucesso
            }

            return false; // Token não encontrado
        }

        public RefreshToken GetByToken(string refreshToken)
        {
            return _context.RefreshTokens.FirstOrDefault(t => t.Token == refreshToken);
        }

        public RefreshToken GetByUserId(long usuarioid)
        {
            return _context.Set<RefreshToken>().FirstOrDefault(rt => rt.UsuarioId == usuarioid);
        }

        public RefreshToken GetRefreshToken(string token)
        {
            return _context.RefreshTokens.FirstOrDefault(t => t.Token == token);
        }

        public RefreshToken? GetRefreshTokenByToken(Usuario usuario)
        {
            var found = _context.RefreshTokens.Find(usuario.Id);

            if (found != null)
            {
                RefreshToken refreshToken = new RefreshToken
                {
                    Token = found.Token,
                    Created = DateTime.UtcNow,
                    Expires = DateTime.UtcNow.AddDays(7),
                };

                _context.RefreshTokens.Add(refreshToken);
                _context.SaveChanges();

                return refreshToken;
            }
            else
            {
                return null;
            }
        }

        public List<RefreshToken> GetRefreshTokenByUsuarioId(long id)
        {
            return _context.RefreshTokens
               .Where(t => t.UsuarioId == id)
               .ToList();
        }

        public bool RemoveRefreshToken(RefreshToken refreshToken)
        {
            // Busca o token existente
            var existingToken = _context.RefreshTokens.Find(refreshToken.Id);

            if (existingToken != null)
            {
                _context.RefreshTokens.Remove(existingToken); // Remove o token
                _context.SaveChanges(); // Salva as alterações
                return true; // Token removido com sucesso
            }

            return false; // Token não encontrado
        }

        public bool Revoke(string token, string revokedByIp)
        {
            var refreshToken = _context.Set<RefreshToken>().FirstOrDefault(rt => rt.Token == token);

            if (refreshToken == null || refreshToken.IsRevoked)
            {
                return false; // Token não encontrado ou já revogado
            }

            refreshToken.RevokedByIp = revokedByIp;
            refreshToken.Revoked = DateTime.UtcNow; // Marca como revogado

            _context.SaveChanges();
            return true;
        }

        public void Update(RefreshToken refreshToken)
        {
            var existingToken = _context.RefreshTokens.FirstOrDefault(t => t.Id == refreshToken.Id);

            if (existingToken != null)
            {
                existingToken.Token = refreshToken.Token;
                existingToken.Expires = refreshToken.Expires;
                existingToken.CreatedByIp = refreshToken.CreatedByIp;

                _context.RefreshTokens.Update(existingToken); // Atualiza o token no contexto

                _context.SaveChanges(); // Chamada não aguardada
            }
        }
    }
}
