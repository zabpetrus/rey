using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Threading.Tasks;
using Rey.Domain.Entities.Auth;
using Rey.Domain.Interfaces.IServices;
using Rey.Domain.Interfaces.IRepository;
using Microsoft.IdentityModel.Tokens;
using Rey.Application.Interfaces;
using Rey.Application.ViewModel;

public class AuthenticatorService : IAuthenticatorService
{
    private readonly ITokenService _tokenService;
    private readonly IUsuarioExternoService _usuarioExternoService;
    private readonly IRefreshTokenExternoRepository _refreshTokenRepository;

    public AuthenticatorService(ITokenService tokenService,
                                IUsuarioExternoService usuarioExternoService,
                                IRefreshTokenExternoRepository refreshTokenRepository)
    {
        _tokenService = tokenService;
        _usuarioExternoService = usuarioExternoService;
        _refreshTokenRepository = refreshTokenRepository;
    }

    // Método para gerar um novo AccessToken a partir de um RefreshToken
    public RefreshToken RefreshToken(string accessToken, string refreshToken, string? username)
    {
        // Validar o token de acesso (acessToken) expirado e obter as claims dele
        ClaimsPrincipal principal = _tokenService.GetPrincipalFromExpiredToken(accessToken);

        if (principal == null)
        {
            throw new SecurityTokenException("Token de acesso inválido.");
        }

        // Validar o refresh token no banco de dados
        var storedRefreshToken = _refreshTokenRepository.GetByTokenAsync(refreshToken).Result;
        if (storedRefreshToken == null || storedRefreshToken.IsExpired || storedRefreshToken.IsRevoked)
        {
            throw new SecurityTokenException("Refresh token inválido ou expirado.");
        }

        // Obter o usuário associado ao refresh token
        UsuarioExterno usuario = _usuarioExternoService.GetByIdAsync(storedRefreshToken.UsuarioId).Result;
        if (usuario == null || (username != null && usuario.NomeDeUsuario != username))
        {
            throw new SecurityTokenException("Usuário associado ao token não encontrado.");
        }

        // Gerar um novo token JWT (AccessToken)
        var claims = new List<Claim>
        {
            new Claim(ClaimTypes.Name, usuario.NomeDeUsuario)
        };

        // Adicionar os perfis de usuário como roles
        var perfisDeUsuario = _usuarioExternoService.FetchUserProfilesByUserId(usuario.Id);
        foreach (var perfil in perfisDeUsuario)
        {
            claims.Add(new Claim(ClaimTypes.Role, perfil.Nome));
        }

        // Gerar novo AccessToken
        var newJwtToken = _tokenService.GerarTokenJwtByClaims(claims);

        // Atualizar o refresh token ou criar um novo se necessário
        var newRefreshToken = _tokenService.GenerateRefreshToken();
        storedRefreshToken.Token = newRefreshToken;
        storedRefreshToken.Expires = DateTime.Now.AddDays(7);
        storedRefreshToken.Created = DateTime.Now;

        _refreshTokenRepository.UpdateAsync(storedRefreshToken);  // Atualizar o refresh token no banco

        return storedRefreshToken;
    }

    // Método para revogar tokens de um usuário
    public UsuarioExternoViewModel RevokeToken(string username)
    {
        // Buscar o usuário pelo username
        var usuario = _usuarioExternoService.FindByUsernameAsync(username).Result;

        if (usuario == null)
        {
            throw new Exception("Usuário não encontrado.");
        }

        // Revogar todos os refresh tokens do usuário
        var tokens = _refreshTokenRepository.GetRefreshTokenByUsuarioIdAsync(usuario.Id).Result;

        foreach (var token in tokens)
        {
            token.Revoked = DateTime.UtcNow;
            token.RevokedByIp = "Sistema";  // Pode ser substituído pelo IP de quem fez a requisição
            token.ReasonRevoked = "Token revogado pelo usuário.";
            _refreshTokenRepository.UpdateAsync(token);
        }

        // Retornar uma ViewModel do usuário (pode ser customizado)
        return new UsuarioExternoViewModel
        {
            Id = usuario.Id,
            NomeDeUsuario = usuario.NomeDeUsuario,
            Email = usuario.Email
        };
    }
}
