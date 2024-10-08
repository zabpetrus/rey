using AutoMapper;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using Rey.Domain.Entities;
using Rey.Domain.Entities.Auth;
using Rey.Domain.Interfaces.IRepository;
using Rey.Domain.Interfaces.IServices;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace Rey.Domain.Services
{
    public class TokenService : ITokenService
    {
        private readonly IConfiguration _configuration;
        private readonly IUsuarioExternoService _usuarioExternoService;
        private readonly IRefreshTokenExternoRepository _tokenRepository;
        private readonly IHttpContextAccessor _httpContextAccessor;
        private readonly IMapper _mapper;
        private readonly ILogger<Token> _logger;

        public TokenService(IConfiguration configuration, IUsuarioExternoService usuarioExternoService, IRefreshTokenExternoRepository tokenRepository, IHttpContextAccessor httpContextAccessor, IMapper mapper, ILogger<Token> logger)
        {
            _configuration = configuration;
            _usuarioExternoService = usuarioExternoService;
            _tokenRepository = tokenRepository;
            _httpContextAccessor = httpContextAccessor;
            _mapper = mapper;
            _logger = logger;
        }

        public Token GerarTokenJwtByClaims(List<Claim> claims)
        {
            var token = new Token();

            token.AccessToken = GerarJwt(claims);
            token.RefreshToken = GenerateRefreshToken();
            token.AccessTokenExpiration = DateTime.Now.AddMinutes(7);
            token.RefreshTokenExpiration = DateTime.Now.AddDays(7);

            return token;
        }

        private string GerarJwt(IEnumerable<Claim> claims)
        {
            string secretKey = _configuration["JwtSettings:Secret"];
            if (string.IsNullOrEmpty(secretKey))
            {
                throw new ArgumentNullException("A chave secreta JWT não foi configurada corretamente.");
            }

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secretKey));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(claims),
                Expires = DateTime.Now.AddMinutes(7),
                SigningCredentials = creds,
                Issuer = _configuration["JwtSettings:Issuer"],
                Audience = _configuration["JwtSettings:Audience"]
            };

            var tokenHandler = new JwtSecurityTokenHandler();
            var token = tokenHandler.CreateToken(tokenDescriptor);

            return tokenHandler.WriteToken(token);
        }

        public string GenerateRefreshToken()
        {
            var randomNumber = new byte[32];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(randomNumber);
                return Convert.ToBase64String(randomNumber);
            }
        }

        public RefreshToken GenerateRefreshToken(string createdByIp)
        {
            var randomNumber = new byte[32];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(randomNumber);
            }

            RefreshToken refreshToken = new RefreshToken
            {
                Token = Convert.ToBase64String(randomNumber),
                Created = DateTime.UtcNow,
                Expires = DateTime.UtcNow.AddDays(7), // Defina a expiração do refresh token
                CreatedByIp = createdByIp
            };

            return refreshToken; // Retorne o RefreshToken
        }



        public Token RenovarToken(string refreshToken, List<Claim> claims)
        {
            var novoAccessToken = GerarJwt(claims);

            var token = new Token
            {
                AccessToken = novoAccessToken,
                RefreshToken = GenerateRefreshToken(),
                AccessTokenExpiration = DateTime.Now.AddMinutes(7),
                RefreshTokenExpiration = DateTime.Now.AddDays(7)
            };

            return token;
        }


        public ClaimsPrincipal GetPrincipalFromExpiredToken(string token)
        {
            var secretKey = _configuration["JwtSettings:Secret"];
            if (string.IsNullOrEmpty(secretKey))
            {
                throw new ArgumentNullException("A chave secreta JWT não foi configurada corretamente.");
            }

            var tokenValidationParameters = new TokenValidationParameters
            {
                ValidateAudience = false,
                ValidateIssuer = false,
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secretKey)),
                ValidateLifetime = false
            };

            var tokenHandler = new JwtSecurityTokenHandler();
            var principal = tokenHandler.ValidateToken(token, tokenValidationParameters, out SecurityToken securityToken);
            var jwtSecurityToken = securityToken as JwtSecurityToken;

            if (jwtSecurityToken == null || !jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256, StringComparison.InvariantCultureIgnoreCase))
            {
                throw new SecurityTokenException("Token inválido");
            }

            return principal;
        }

        public async Task<Token> Login(string username, string senha)
        {
            // Verificando se o usuário existe
            UsuarioExterno usuario =
                await _usuarioExternoService.FindUserByCpfAsync(username) ??
                await _usuarioExternoService.FindUserByEmailAsync(username) ??
                await _usuarioExternoService.FindByUsernameAsync(username);

            if (usuario == null)
            {
                throw new Exception("Usuário não encontrado.");
            }

            // Verificando a senha do usuário
            if (!usuario.VerificarSenha(senha))
            {
                throw new UnauthorizedAccessException("Usuário ou senha inválidos.");
            }

            // Obtendo os perfis relacionados ao usuário
            List<PerfilExterno> perfisDeUsuario = _usuarioExternoService.FetchUserProfilesByUserId(usuario.Id);

            // Gerar claims para o JWT com base nas informações do usuário
            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, usuario.NomeDeUsuario)
            };

            // Adicionar os perfis como roles
            foreach (var perfil in perfisDeUsuario)
            {
                claims.Add(new Claim(ClaimTypes.Role, perfil.Nome));
            }

            // Gerar o token JWT
            Token token = GerarTokenJwtByClaims(claims);

            // Criar e salvar o refresh token no banco de dados
            RefreshToken refreshToken = new RefreshToken
            {
                Token = GenerateRefreshToken(),
                Expires = DateTime.Now.AddDays(7), // Definir a expiração do refresh token
                Created = DateTime.Now,
                CreatedByIp = _httpContextAccessor.HttpContext?.Connection.RemoteIpAddress?.ToString() // Obtém o IP do cliente
            };

            RefreshToken refreshed = await _tokenRepository.CreateAsync(refreshToken);

            token.RefreshToken = refreshed.ReplacedByToken; // Atribuir o refresh token ao objeto de retorno
            return token; // Retornar o token
        }




        public async Task<Token> RefreshToken(string refreshToken, string ipadress)
        {
            // Validar se o refresh token existe no banco de dados
            RefreshToken token = await _tokenRepository.GetByTokenAsync(refreshToken);
            if (token == null || token.Expires < DateTime.Now)
            {
                throw new SecurityTokenException("Refresh token inválido ou expirado.");
            }

            // Validar o usuário associado ao refresh token
            UsuarioExterno usuario = await _usuarioExternoService.GetByIdAsync(token.UsuarioId);
            if (usuario == null)
            {
                throw new SecurityTokenException("Usuário associado ao token não encontrado.");
            }

            // Criar um novo JWT baseado nas claims do usuário
            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, usuario.NomeDeUsuario),

            };

            // Obtendo os perfis relacionados ao usuário
            List<PerfilExterno> perfisDeUsuario = _usuarioExternoService.FetchUserProfilesByUserId(usuario.Id);

            // Adicionar os perfis como roles
            foreach (var perfil in perfisDeUsuario)
            {
                claims.Add(new Claim(ClaimTypes.Role, perfil.Nome));
            }

            var novoAccessToken = GerarTokenJwtByClaims(claims);

            // Atualizar o refresh token ou criar um novo se necessário
            var novoRefreshToken = GenerateRefreshToken();
            token.Token = novoRefreshToken;
            token.Expires = DateTime.Now.AddDays(7);
            token.Created = DateTime.Now;
            token.CreatedByIp = ipadress;

            await _tokenRepository.UpdateAsync(token);  // Atualizar o token no banco

            return new Token
            {
                AccessToken = novoAccessToken.AccessToken,
                RefreshToken = novoRefreshToken,
                AccessTokenExpiration = DateTime.Now.AddMinutes(7),
                RefreshTokenExpiration = DateTime.Now.AddDays(7)
            };
        }

        public async Task<bool> ResetPassword(string token, string novasenha)
        {
            // Validar o token de reset de senha e procurar o usuário correspondente

            _logger.LogInformation("Iniciando processo de redefinição de senha.");


            UsuarioExterno usuario = await _usuarioExternoService.GetByResetPasswordTokenAsync(token);

            if (usuario == null || string.IsNullOrEmpty(novasenha))
            {
                _logger.LogWarning("Token inválido ou expirado para redefinição de senha.");
                return false;
            }

            // Redefinir a senha (criptografar a nova senha antes de armazenar)
            usuario.CriarHashSenha(novasenha);
            usuario.RefreshTokenReset = null;  // Remover o token de reset após o uso
            usuario.ResetPasswordTokenExpiration = null;

            if (await _usuarioExternoService.UpdateAsync(usuario))
            {
                _logger.LogInformation("Senha redefinida com sucesso.");
                  return true;
            }// Atualizar a senha no banco

            return false;
           
        }

        public async Task<UsuarioExterno> Register(Registration registration)
        {

            UsuarioExterno usuarioExistente = await _usuarioExternoService.FindUserByCpfAsync(registration.Cpf) ??
               await _usuarioExternoService.FindUserByEmailAsync(registration.Email);


            if (usuarioExistente != null)
            {
                throw new InvalidOperationException("Este usuário já está registrado.");
            }

            UsuarioExterno novo = _mapper.Map<UsuarioExterno>(registration);

            novo.CriarHashSenha(registration.HashSenha);

            UsuarioExterno criado = await _usuarioExternoService.CreateAsync(novo);  // Salvar o novo usuário no banco

            return criado;
        }

        // --- Revogar todos os tokens para o usuário ---
        public async Task<bool> RevogarTodosTokens(string username)
        {
            // Buscar o usuário no banco de dados
            UsuarioExterno usuario =
              await _usuarioExternoService.FindUserByCpfAsync(username) ??
              await _usuarioExternoService.FindUserByEmailAsync(username) ??
              await _usuarioExternoService.FindByUsernameAsync(username);

            if (usuario == null)
            {
                return false; // Usuário não encontrado
            }

            // Buscar todos os tokens de refresh associados ao usuário
            List<RefreshToken> tokens = await _tokenRepository.GetRefreshTokenByUsuarioIdAsync(usuario.Id);
            if (tokens == null || !tokens.Any())
            {
                return false; // Não há tokens para este usuário
            }

            // Remover todos os tokens do banco de dados
            foreach (var token in tokens)
            {
                await _tokenRepository.DeleteById(token.Id);
            }

            return true;
        }

        public async Task<bool> RevokeTokens(string token)
        {
            try
            {
                // Verifica se o Refresh Token existe no banco de dados
                RefreshToken refreshToken = await _tokenRepository.GetRefreshTokenAsync(token);

                if (refreshToken == null)
                {
                    _logger.LogWarning($"Tentativa de revogar um token inexistente: {token}");
                    return false; // Token não encontrado
                }

                // Revogar o token removendo-o do banco de dados
                bool revoked = await _tokenRepository.RemoveRefreshTokenAsync(refreshToken);

                if (revoked)
                {
                    _logger.LogInformation($"Token revogado com sucesso: {token}");
                    return true;
                }
                else
                {
                    _logger.LogWarning($"Falha ao revogar o token: {token}");
                    return false;
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Erro ao tentar revogar o token: {token}");
                return false;
            }
        }

    }
}
