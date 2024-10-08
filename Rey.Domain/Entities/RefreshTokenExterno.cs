using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Text;
using System.Text.Json.Serialization;
using System.Threading.Tasks;

namespace Rey.Domain.Entities
{
    public class RefreshTokenExterno
    {

        [Key]
        [JsonIgnore]
        public long Id { get; set; }

        public long UserId { get; set; }

        public string Token { get; set; }

        // Data e hora em que o token expira
        public DateTime Expires { get; set; }

        // Data e hora em que o token foi criado
        public DateTime Created { get; set; }

        // IP do cliente que criou o token
        public string CreatedByIp { get; set; }

        // Data e hora em que o token foi revogado (se aplicável)
        public DateTime? Revoked { get; set; }

        // IP do cliente que revogou o token
        public string RevokedByIp { get; set; }

        // Token que substitui este token, se aplicável
        public string ReplacedByToken { get; set; }

        // Motivo da revogação do token
        public string ReasonRevoked { get; set; }

        // Verifica se o token está expirado
        public bool IsExpired => DateTime.UtcNow >= Expires;

        // Verifica se o token foi revogado
        public bool IsRevoked => Revoked != null;

        // Verifica se o token é ativo (não revogado e não expirado)
        public bool IsActive => !IsRevoked && !IsExpired;
    }
}
