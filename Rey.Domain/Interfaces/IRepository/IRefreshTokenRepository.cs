using Rey.Domain.Entities.Auth;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Rey.Domain.Interfaces.IRepository
{
    public interface IRefreshTokenRepository
    {
        RefreshToken Create(RefreshToken refreshToken);
        RefreshToken CreateRefreshToken(string token);
        bool DeleteById(long id);
        RefreshToken GetByToken(string refreshToken);
        RefreshToken GetByUserId(long usuarioid);
        RefreshToken GetRefreshToken(string token);
        RefreshToken? GetRefreshTokenByToken(Usuario usuario);
        List<RefreshToken> GetRefreshTokenByUsuarioId(long id);
        bool RemoveRefreshToken(RefreshToken refreshToken);
        bool Revoke(string token, string revokedByIp);
        void Update(RefreshToken refreshToken);
    }
}
