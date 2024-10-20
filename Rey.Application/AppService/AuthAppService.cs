using AutoMapper;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using Rey.Application.Interfaces;
using Rey.Application.ViewModel;
using Rey.Domain.Entities.Auth;
using Rey.Domain.Entities.Dto;
using Rey.Domain.Enums;
using Rey.Domain.Interfaces.IServices;
using Rey.Domain.Services;
using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace Rey.Application.AppService
{
    public class AuthAppService : IAuthAppService
    {
        private readonly ITokenService _tokenService;
        private readonly ILogger<AuthAppService> _logger;
        private readonly IMapper _mapper;
        private readonly IUsuarioExternoService _usuarioExternoService;
        private readonly IConfiguration _configuration;
        private readonly IHttpContextAccessor _httpContextAccessor;
        private readonly IRefreshTokenService _refreshTokenService;

        public AuthAppService(ITokenService tokenService, ILogger<AuthAppService> logger, IMapper mapper, IUsuarioExternoService userService, IConfiguration configuration)
        {
            _tokenService = tokenService;
            _logger = logger;
            _mapper = mapper;
            _usuarioExternoService = userService;
            _configuration = configuration;
        }

        public Task<bool> ForgotPassword(ForgotPasswordViewModel model)
        {
            throw new NotImplementedException();
        }

        public ClaimsPrincipal GetPrincipalFromExpiredToken(string token)
        {
            string secretKey = _configuration["JwtSettings:Secret"];

            if (string.IsNullOrEmpty(secretKey))
            {
                throw new ArgumentNullException("A chave secreta JWT não foi configurada corretamente.");
            }

            var tokenValidationParameters = new TokenValidationParameters
            {
                ValidateAudience = true,
                ValidateIssuer = true,
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secretKey)),
                ValidateLifetime = true
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

        public Task<TokenViewModel> Login(LoginRequestViewModel request)
        {
            throw new NotImplementedException();
        }

        public TokenResult? LoginInterno(string username, string senha)
        {
            // Buscando o usuário baseado em CPF, email ou nome de usuário
            UsuarioExterno usuario =
                _usuarioExternoService.FindUserByCpf(username) ??
                _usuarioExternoService.FindUserByEmail(username) ??
                _usuarioExternoService.FindByUsername(username);

            if (usuario == null)
            {
                throw new Exception("Usuário não encontrado.");
            }

            if (!usuario.VerificarSenha(senha))
            {
                throw new UnauthorizedAccessException("Usuário ou senha inválidos.");
            }

            List<Claim> listaclaims = new()
            {
                new Claim(ClaimTypes.Name, usuario.Nome),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new Claim(ClaimTypes.Role, "admin"),
                new Claim("usuario", usuario.Id.ToString())
            };

            int accessTokenValidityInMinutes = int.Parse(_configuration["JWTSettings:AccessTokenExpirationInMinutes"]);
            int refreshTokenValidityInDays = int.Parse(_configuration["JWTSettings:RefreshTokenExpirationInDays"]);


            // Gera o token JWT
            TokenResult token = new()
            {
                AccessToken = _tokenService.GenerateToken(listaclaims),
                RefreshToken = _tokenService.GenerateRefreshToken(),
                AccessTokenExpiration = DateTime.UtcNow.AddMinutes(accessTokenValidityInMinutes),
                RefreshTokenExpiration = DateTime.UtcNow.AddDays(refreshTokenValidityInDays),
            };

            RevokeToken tokenrevogado = _tokenService.ResolveRevokedIpUser(usuario);


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
                ReplacedByToken = tokenrevogado.NewToken ?? "",
                UsuarioId = usuario.Id,
                TipoUsuario = TipoUsuario.Externo, // Adicionando o tipo de usuário, se necessário
    
            };

            _refreshTokenService.Create(refreshToken); // Salvando o RefreshToken no banco

            return token; // Retornando o token gerado
        }

        public Task<bool> Logout(LogoutViewModel model)
        {
            throw new NotImplementedException();
        }

        public Task<TokenViewModel> RefreshToken(RefreshTokenRequest request)
        {
            throw new NotImplementedException();
        }

        public Task Register(RegisterViewModel model)
        {
            throw new NotImplementedException();
        }

        public Task<bool> ResetPassword(ResetPasswordViewModel model)
        {
            throw new NotImplementedException();
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
            RefreshToken tokens = _refreshTokenService.GetByUserId(usuario.Id);

            // Retornar uma ViewModel do usuário (pode ser customizado)
            return new UsuarioExternoViewModel
            {
                Id = usuario.Id,
                Nome = usuario.Nome,
                Email = usuario.Email
            };
        }

        public Task<bool> VerifyAccount(string token)
        {
            throw new NotImplementedException();
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



    }
}
