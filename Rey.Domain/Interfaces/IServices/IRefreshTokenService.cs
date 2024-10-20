using Rey.Domain.Entities;
using Rey.Domain.Entities.Auth;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Rey.Domain.Interfaces.IServices
{
    public interface IRefreshTokenService
    {
        RefreshToken Create(RefreshToken refreshToken);

        RefreshToken CreateRefreshToken(string token);

        RefreshToken GetByUserId(long usuarioid);

        void Update(RefreshToken refreshToken);

        bool Revoke(string token, string revokedByIp);

        bool DeleteById(long id);

        bool RemoveRefreshToken(RefreshToken refreshToken);
    }
}
