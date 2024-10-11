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
    public class RefreshTokenExternoService : IRefreshTokenExternoService
    {
        private readonly IRefreshTokenExternoRepository _repository;

        public RefreshTokenExternoService(IRefreshTokenExternoRepository repository)
        {
            _repository = repository;
        }

        public RefreshToken Create(RefreshToken refreshToken)
        {
            return _repository.Create(refreshToken);    
        }

        public Task<RefreshToken> CreateAsync(RefreshToken refreshToken)
        {
            return _repository.CreateAsync(refreshToken);
        }

        public Task<RefreshToken> CreateRefreshTokenAsync(string token)
        {
            return _repository.CreateRefreshTokenAsync(token);  
        }
      
        public Task<bool> DeleteById(long id)
        {
            return _repository.DeleteById(id);
        }

        public Task<RefreshToken> GetByTokenAsync(string token)
        {
            return _repository.CreateRefreshTokenAsync(token);
        }

        public Task<RefreshToken> GetByUserIdAsync(long usuarioid)
        {
            return _repository.GetByUserIdAsync(usuarioid);
        }

      
        public Task<bool> RemoveRefreshTokenAsync(RefreshToken refreshToken)
        {
            return _repository.RemoveRefreshTokenAsync(refreshToken);   
        }

        public Task<bool> RevokeAsync(string token, string revokedByIp)
        {
            return _repository.RevokeAsync(token, revokedByIp);
        }

        public Task<RefreshToken> UpdateAsync(RefreshToken refreshToken)
        {
            return _repository.UpdateAsync(refreshToken);
        }           
    }
}
