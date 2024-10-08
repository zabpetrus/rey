using Rey.Domain.Entities.Auth;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Rey.Domain.Interfaces.IRepository
{
    public interface IRefreshTokenExternoRepository
    {
        Task<RefreshToken> CreateAsync(RefreshToken refreshToken);

        RefreshToken Create(RefreshToken refreshToken);

        Task<RefreshToken> GetByTokenAsync(string token);

        Task<List<RefreshToken>> GetByUserIdAsync(long userId);

        Task<RefreshToken> UpdateAsync(RefreshToken refreshToken);

        Task<bool> RevokeAsync(string token, string revokedByIp);

        Task<bool> DeleteAsync(long id);
        Task<List<RefreshToken>> GetRefreshTokenByUsuarioIdAsync(long id);
        Task DeleteById(long id);
        Task<RefreshToken> GetRefreshTokenAsync(string token);
        Task<bool> RemoveRefreshTokenAsync(RefreshToken refreshToken);
    }
}
