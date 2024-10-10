using Rey.Domain.Enums;
using System;
using System.ComponentModel.DataAnnotations;
using System.Text.Json.Serialization;

namespace Rey.Domain.Entities.Auth
{
    public class RefreshToken
    {
        [Key]
        [JsonIgnore]
        public long Id { get; set; }

        public long UsuarioId { get; set; }

        public TipoUsuario TipoUsuario { get; set; }

        // O token de refresh
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


        // Propriedades adicionais para gerenciamento de reset


        // Token para reset de refresh token
        public string RefreshTokenReset { get; internal set; }

        // Expiração do refresh token
        public DateTime? RefreshTokenExpiryTime { get; internal set; }

        // Expiração do token de redefinição de senha
        public string ResetPasswordTokenExpiration { get; internal set; }

        // Conversão implícita para string
        public static implicit operator string(RefreshToken refreshToken) => refreshToken.Token;

        // Conversão implícita de string para RefreshToken
        public static implicit operator RefreshToken(string token) => new RefreshToken { Token = token };
    }
}
