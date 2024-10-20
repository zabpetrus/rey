using Rey.Domain.Entities.Auth;
using Rey.Domain.Interfaces.IRepository;
using Rey.Domain.Interfaces.IServices;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Rey.Domain.Services
{
    public class RefreshTokenExternoService : IRefreshTokenService
    {
        private readonly IRefreshTokenRepository _repository;

        public RefreshTokenExternoService(IRefreshTokenRepository repository)
        {
            _repository = repository;
        }

        public RefreshToken Create(RefreshToken refreshToken)
        {
            // Chamada síncrona ao repositório para criar o refresh token
            return _repository.Create(refreshToken);
        }

        public RefreshToken CreateRefreshToken(string token)
        {
            // Chamada síncrona ao repositório para criar um novo refresh token a partir de um token
            return _repository.CreateRefreshToken(token);
        }

        public bool DeleteById(long id)
        {
            // Chamada síncrona ao repositório para deletar um refresh token pelo ID
            return _repository.DeleteById(id);
        }

        public RefreshToken GetByUserId(long usuarioid)
        {
            // Chamada síncrona ao repositório para obter um refresh token pelo ID do usuário
            return _repository.GetByUserId(usuarioid);
        }

        public bool RemoveRefreshToken(RefreshToken refreshToken)
        {
            // Chamada síncrona ao repositório para remover um refresh token
            return _repository.RemoveRefreshToken(refreshToken);
        }

        public bool Revoke(string token, string revokedByIp)
        {
            // Chamada síncrona ao repositório para revogar um refresh token
            return _repository.Revoke(token, revokedByIp);
        }

        public void Update(RefreshToken refreshToken)
        {
            // Chamada síncrona ao repositório para atualizar um refresh token
            _repository.Update(refreshToken);
        }
    }

}

