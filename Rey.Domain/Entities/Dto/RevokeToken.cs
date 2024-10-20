using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Rey.Domain.Entities.Dto
{
    public class RevokeToken
    {
        public DateTime? Revoked { get; set; }  // Data de revogação
        public string RevokedByIp { get; set; }  // IP que revogou
        public bool IsRevoked { get; set; }      // Indica se o token foi revogado
        public string NewToken { get; set; }     // Token substituto (se houver)
        public string ReasonRevoked { get; set; } // Motivo da revogação
    }
}

