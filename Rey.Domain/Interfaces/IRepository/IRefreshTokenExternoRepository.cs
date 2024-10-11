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

        Task<RefreshToken> CreateRefreshTokenAsync(string token);

        Task<RefreshToken> GetByUserIdAsync(long usuarioid);

        Task<RefreshToken> UpdateAsync(RefreshToken refreshToken);

        Task<bool> RevokeAsync(string token, string revokedByIp);

        Task<bool> DeleteById(long id);

        Task<bool> RemoveRefreshTokenAsync(RefreshToken refreshToken);
        RefreshToken GetByTokenAsync(string refreshToken);
        Task<RefreshToken> GetRefreshTokenAsync(string token);
        Task<List<RefreshToken>> GetRefreshTokenByUsuarioIdAsync(long id);
    }
}
