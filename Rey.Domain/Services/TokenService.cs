using AutoMapper;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json.Linq;
using Rey.Domain.Entities;
using Rey.Domain.Entities._Abstract;
using Rey.Domain.Entities.Auth;
using Rey.Domain.Entities.Dto;
using Rey.Domain.Enums;
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
        private readonly IRefreshTokenRepository _tokenRepository;
        private readonly IHttpContextAccessor _httpContextAccessor;
        private readonly IMapper _mapper;
        private readonly ILogger<Token> _logger;

        public TokenService(IConfiguration configuration, IUsuarioExternoService usuarioExternoService, IRefreshTokenRepository tokenRepository, IHttpContextAccessor httpContextAccessor, IMapper mapper, ILogger<Token> logger)
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

            token.AccessToken = GerarJwtWithClaims(claims);
            token.RefreshToken = GenerateRefreshToken();
            token.AccessTokenExpiration = DateTime.UtcNow.AddMinutes(7);
            token.RefreshTokenExpiration = DateTime.UtcNow.AddDays(7);

            return token;
        }

        public Token GerarTokenJwt()
        {
            var token = new Token();

            // Gerar o JWT sem claims
            token.AccessToken = GerarJwt();

            // Gerar o Refresh Token (pode ser uma string aleatória ou algo mais seguro)
            token.RefreshToken = GenerateRefreshToken();

            // Configurar a expiração do Access Token (7 minutos)
            token.AccessTokenExpiration = DateTime.UtcNow.AddMinutes(7);

            // Configurar a expiração do Refresh Token (7 dias)
            token.RefreshTokenExpiration = DateTime.UtcNow.AddDays(7);

            return token;
        }


        private string GerarJwt()
        {
            // Recuperando a chave secreta do arquivo de configuração
            string secretKey = _configuration["JWTSettings:Secret"];
            if (string.IsNullOrEmpty(secretKey))
            {
                throw new ArgumentNullException("A chave secreta JWT não foi configurada corretamente.");
            }

            // Configurando a chave de assinatura usando HMAC-SHA256
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secretKey));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            // Recuperando o tempo de expiração diretamente como inteiro
            if (!int.TryParse(_configuration["JWTSettings:AccessTokenExpirationInMinutes"], out int expirationMinutes))
            {
                throw new ArgumentException("A configuração do tempo de expiração do token JWT está inválida.");
            }

            // Definindo a data e hora atual como "não antes" e calculando a data de expiração
            var notBefore = DateTime.UtcNow;
            var expires = notBefore.AddMinutes(expirationMinutes);

            // Verificando se Issuer e Audience estão configurados corretamente
            var issuer = _configuration["JWTSettings:ValidIssuer"];
            var audience = _configuration["JWTSettings:ValidAudience"];
            if (string.IsNullOrEmpty(issuer) || string.IsNullOrEmpty(audience))
            {
                throw new ArgumentNullException("Issuer ou Audience não estão configurados corretamente.");
            }

            // Montando o SecurityTokenDescriptor sem claims
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Expires = expires,
                NotBefore = notBefore,
                SigningCredentials = creds,
                Issuer = issuer,
                Audience = audience
            };

            // Criando e escrevendo o token JWT
            var tokenHandler = new JwtSecurityTokenHandler();
            var token = tokenHandler.CreateToken(tokenDescriptor);

            return tokenHandler.WriteToken(token);
        }




        private string GerarJwtWithClaims(IEnumerable<Claim> claims)
        {
            string secretKey = _configuration["JWTSettings:Secret"];
            if (string.IsNullOrEmpty(secretKey))
            {
                throw new ArgumentNullException("A chave secreta JWT não foi configurada corretamente.");
            }

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secretKey));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            var expirationMinutes = double.Parse(_configuration["JWTSettings:AccessTokenExpirationInMinutes"]);

            // Crie a data de não antes como a hora atual
            var notBefore = DateTime.UtcNow;  // Defina a hora de "não antes"
            var expires = notBefore.AddMinutes(expirationMinutes); // A data de expiração deve ser definida com base em "não antes"

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(claims),
                Expires = expires,  // Use a data de expiração calculada
                NotBefore = notBefore,  // Define o "não antes" como agora
                SigningCredentials = creds,
                Issuer = _configuration["JWTSettings:ValidIssuer"],
                Audience = _configuration["JWTSettings:ValidAudience"]
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
                Expires = DateTime.UtcNow.AddDays(7),
                ReasonRevoked = null, // Defina um valor significativo se necessário ou mantenha como null se a coluna permitir
                Created = DateTime.UtcNow, // Uso de UTC para consistência
                CreatedByIp = createdByIp,
                Revoked = null, // Mantenha como null se o token não for revogado imediatamente
                RevokedByIp = null, // Mantenha como null se não houver revogação
                ReplacedByToken = null, // Mantenha como null se não houver substituição
                UsuarioId = 0, // Defina um ID de usuário válido se aplicável
                TipoUsuario = TipoUsuario.Externo, // Adicionando o tipo de usuário, se necessário
                RefreshTokenReset = null, // Mantenha como null se não for necessário
                RefreshTokenExpiryTime = DateTime.UtcNow.AddDays(7), // Definindo um tempo de expiração correto
                ResetPasswordTokenExpiration = null, // Mantenha como null se não houver expiração
            };

            return refreshToken; // Retorne o RefreshToken
        }


        public Token RenovarToken(string refreshToken, List<Claim> claims)
        {
            // Verificar se o Refresh Token ainda é válido
            RefreshToken tokenNoBanco = _tokenRepository.GetByToken(refreshToken);

            if (tokenNoBanco == null || tokenNoBanco.Expires < DateTime.UtcNow)
            {
                throw new SecurityTokenException("Refresh token inválido ou expirado.");
            }

            // Gerar um novo Access Token
            string novoAccessToken = GerarJwt();

            // Atualizar o Refresh Token se necessário (caso ele esteja próximo da expiração)
            if (tokenNoBanco.Expires < DateTime.UtcNow.AddDays(1))
            {
                var novoRefreshToken = GenerateRefreshToken();
                tokenNoBanco.Token = novoRefreshToken;
                tokenNoBanco.Expires = DateTime.UtcNow.AddDays(7);

                //Atualizar o Token no banco
                _tokenRepository.Update(tokenNoBanco);
            }

            return new Token
            {
                AccessToken = novoAccessToken,
                RefreshToken = tokenNoBanco.Token, 
                AccessTokenExpiration = DateTime.UtcNow.AddMinutes(7),
                RefreshTokenExpiration = tokenNoBanco.Expires
            };
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
            // Buscando o usuário baseado em CPF, email ou nome de usuário
            UsuarioExterno usuario =
                await _usuarioExternoService.FindUserByCpfAsync(username) ??
                await _usuarioExternoService.FindUserByEmailAsync(username) ??
                await _usuarioExternoService.FindByUsernameAsync(username);

            if (usuario == null)
            {
                throw new Exception("Usuário não encontrado.");
            }

            if (!usuario.VerificarSenha(senha))
            {
                throw new UnauthorizedAccessException("Usuário ou senha inválidos.");
            }

            

            // Gera o token JWT
            Token token = GerarTokenJwt();

            RevokeToken tokenrevogado = ResolveRevokedIpUser(usuario);


            // Criando e salvando o Refresh Token
            RefreshToken refreshToken = new RefreshToken
            {
                Token = token.RefreshToken,
                Expires = token.RefreshTokenExpiration,
                ReasonRevoked = tokenrevogado.ReasonRevoked ?? "",
                Created = DateTime.UtcNow, // Uso de UTC para consistência
                CreatedByIp = _httpContextAccessor.HttpContext?.Connection.RemoteIpAddress?.ToString(),
                Revoked = tokenrevogado.Revoked ?? DateTime.UtcNow.AddDays(7),
                RevokedByIp = tokenrevogado.RevokedByIp ?? "",
                ReplacedByToken = tokenrevogado.NewToken  ?? "",
                UsuarioId = usuario.Id,
                TipoUsuario = TipoUsuario.Externo, // Adicionando o tipo de usuário, se necessário
                RefreshTokenReset = "",
                RefreshTokenExpiryTime = DateTime.UtcNow,
                ResetPasswordTokenExpiration = "",
            };

            _tokenRepository.Create(refreshToken); // Salvando o RefreshToken no banco

            return token; // Retornando o token gerado
        }

        private RevokeToken ResolveRevokedIpUser(UsuarioExterno usuario)
        {
            // Busca o refresh token associado
            RefreshToken refreshToken =  _tokenRepository.GetRefreshTokenByToken(usuario);

            // Se o token não for encontrado, retorne um objeto indicando que o token não está revogado
            if (refreshToken == null)
            {
                return new RevokeToken
                {
                    IsRevoked = false
                };
            }

            // Se o token já foi revogado, retorne as informações de revogação
            if (refreshToken.IsRevoked)
            {
                return new RevokeToken
                {
                    Revoked = refreshToken.Revoked,
                    RevokedByIp = refreshToken.RevokedByIp,
                    IsRevoked = true,
                    ReasonRevoked = refreshToken.ReasonRevoked,
                    NewToken = refreshToken.ReplacedByToken // Se um novo token substituiu este, inclua-o
                };
            }

            string currentIpAddress = _httpContextAccessor.HttpContext?.Connection.RemoteIpAddress?.ToString();


            // Verifica se o IP atual é diferente do IP que criou o token (possível atividade suspeita)
            if (refreshToken.CreatedByIp != currentIpAddress)
            {
                // Revoga o token devido ao IP suspeito
                refreshToken.Revoked = DateTime.UtcNow;
                refreshToken.RevokedByIp = currentIpAddress;
                refreshToken.ReasonRevoked = "IP suspeito detectado";

                // Salva as mudanças no banco de dados
                _tokenRepository.Update(refreshToken);

                // Retorna as informações de revogação
                return new RevokeToken
                {
                    Revoked = refreshToken.Revoked,
                    RevokedByIp = refreshToken.RevokedByIp,
                    IsRevoked = true,
                    ReasonRevoked = refreshToken.ReasonRevoked
                };
            }

            // Se o token expirou, revogue e retorne as informações
            if (refreshToken.IsExpired)
            {
                refreshToken.Revoked = DateTime.UtcNow;
                refreshToken.RevokedByIp = currentIpAddress;
                refreshToken.ReasonRevoked = "Token expirado";

                _tokenRepository.Update(refreshToken);

                return new RevokeToken
                {
                    Revoked = refreshToken.Revoked,
                    RevokedByIp = refreshToken.RevokedByIp,
                    IsRevoked = true,
                    ReasonRevoked = refreshToken.ReasonRevoked
                };
            }

            // Se o token ainda está ativo, nenhum revogação foi realizada
            return new RevokeToken
            {
                IsRevoked = false
            };
        }


        public async Task<Token> LoginOriginal(string username, string senha)
        {
            UsuarioExterno usuario =
                await _usuarioExternoService.FindUserByCpfAsync(username) ??
                await _usuarioExternoService.FindUserByEmailAsync(username) ??
                await _usuarioExternoService.FindByUsernameAsync(username);

            if (usuario == null)
            {
                throw new Exception("Usuário não encontrado.");
            }

            if (!usuario.VerificarSenha(senha))
            {
                throw new UnauthorizedAccessException("Usuário ou senha inválidos.");
            }

            List<PerfilExterno> perfisDeUsuario = _usuarioExternoService.FetchUserProfilesByUserId(usuario.Id);

            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, usuario.Nome),
            };

            foreach (var perfil in perfisDeUsuario)
            {
                claims.Add(new Claim(ClaimTypes.Role, perfil.Codigo));
            }

            Token token = GerarTokenJwtByClaims(claims);

            // Gerar e salvar o Refresh Token no banco de dados
            RefreshToken refreshToken = new RefreshToken
            {
                Token = token.RefreshToken,
                Expires = token.RefreshTokenExpiration,
                Created = DateTime.UtcNow,
                CreatedByIp = _httpContextAccessor.HttpContext?.Connection.RemoteIpAddress?.ToString(),
                UsuarioId = usuario.Id
            };

            _tokenRepository.Create(refreshToken); // Salvando o RefreshToken no banco

            return token;
        }

        public async Task<Token> RefreshToken(string refreshToken, string ipadress)
        {
            // Validar se o refresh token existe no banco de dados
            RefreshToken token = _tokenRepository.GetByToken(refreshToken);
            if (token == null || token.Expires < DateTime.UtcNow)
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
                new Claim(ClaimTypes.Name, usuario.Nome),

            };

            // Obtendo os perfis relacionados ao usuário
            List<PerfilExterno> perfisDeUsuario = _usuarioExternoService.FetchUserProfilesByUserId(usuario.Id);

            // Adicionar os perfis como roles
            foreach (var perfil in perfisDeUsuario)
            {
                claims.Add(new Claim(ClaimTypes.Role, perfil.Codigo));
            }

            var novoAccessToken = GerarTokenJwtByClaims(claims);

            // Atualizar o refresh token ou criar um novo se necessário
            var novoRefreshToken = GenerateRefreshToken();
            token.Token = novoRefreshToken;
            token.Expires = DateTime.UtcNow.AddDays(7);
            token.Created = DateTime.UtcNow;
            token.CreatedByIp = ipadress;

            _tokenRepository.Update(token);  // Atualizar o token no banco

            return new Token
            {
                AccessToken = novoAccessToken.AccessToken,
                RefreshToken = novoRefreshToken,
                AccessTokenExpiration = DateTime.UtcNow.AddMinutes(7),
                RefreshTokenExpiration = DateTime.UtcNow.AddDays(7)
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
            usuario.RedefinirSenha(novasenha);
         

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

            novo.VerificarSenha(registration.HashSenha);

            UsuarioExterno criado = await _usuarioExternoService.CreateAsync(novo);  // Salvar o novo usuário no banco

            return criado;
        }

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
            List<RefreshToken> tokens = _tokenRepository.GetRefreshTokenByUsuarioId(usuario.Id);
            if (tokens == null || !tokens.Any())
            {
                return false; // Não há tokens para este usuário
            }

            // Remover todos os tokens do banco de dados
            foreach (var token in tokens)
            {
                _tokenRepository.DeleteById(token.Id);
            }

            return true;
        }

        public async Task<bool> RevokeTokens(string token)
        {
            try
            {
                // Verifica se o Refresh Token existe no banco de dados
                RefreshToken refreshToken = _tokenRepository.GetRefreshToken(token);

                if (refreshToken == null)
                {
                    _logger.LogWarning($"Tentativa de revogar um token inexistente: {token}");
                    return false; // Token não encontrado
                }

                // Revogar o token removendo-o do banco de dados
                bool revoked =  _tokenRepository.RemoveRefreshToken(refreshToken);

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

        private async Task<List<Claim>> GetClaims(UsuarioExterno usuario)
        {

            List<PermissaoExterno> permissaoExternos = _usuarioExternoService.FetchUserPermissionByUserId(usuario.Id);
            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, usuario.Nome),
            };

            foreach (PermissaoExterno permissao in permissaoExternos)
            {
                claims.Add(new Claim("Permission", permissao.Nome));
            }

            return claims;
        }



        private async Task<List<Claim>> GetRoles(UsuarioExterno usuario)
        {

            List<PerfilExterno> perfisDeUsuario = _usuarioExternoService.FetchUserProfilesByUserId(usuario.Id);
            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, usuario.Nome),
            };

            foreach (var perfil in perfisDeUsuario)
            {
                claims.Add(new Claim(ClaimTypes.Role, perfil.Codigo));
            }

            return claims;
        }

        public RefreshToken? GetByToken(string token)
        {
            throw new NotImplementedException();
        }

        public RefreshToken GetRefreshToken(string refreshToken)
        {
            throw new NotImplementedException();
        }

        public List<RefreshToken> FindTokensByUser(UsuarioExterno externo)
        {
            throw new NotImplementedException();
        }

        public RefreshToken CreateAndGet(RefreshToken refresh)
        {
            throw new NotImplementedException();
        }

        public bool RemoveRefreshToken(RefreshToken refreshToken)
        {
            throw new NotImplementedException();
        }

        public void DeleteById(long id)
        {
            throw new NotImplementedException();
        }

        public List<RefreshToken> GetRefreshTokenByUsuarioId(long usuarioId)
        {
            throw new NotImplementedException();
        }

        string ITokenService.GerarJwt()
        {
            throw new NotImplementedException();
        }

        public string GenerateToken(List<Claim> listaclaims)
        {
            throw new NotImplementedException();
        }

        RevokeToken ITokenService.ResolveRevokedIpUser(UsuarioExterno usuario)
        {
            throw new NotImplementedException();
        }
    }
}
