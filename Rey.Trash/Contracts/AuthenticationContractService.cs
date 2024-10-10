using AutoMapper;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using Rey.Domain.Entities;
using Rey.Domain.Interfaces.IServices;
using Rey.Trash.Dto;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Rey.Trash.Contracts
{
    internal sealed class AuthenticationContractService : IAuthenticationContractService
    {
        private readonly IMapper _mapper;
        private readonly ILogger _logger;
        private readonly UserManager<UsuarioExterno> _userManager;
        private readonly IConfiguration _configuration;
        private readonly IUsuarioExternoService _usuarioPerfilExternoService;

        private readonly UsuarioExterno? _usuarioExterno;

        public AuthenticationContractService(IMapper mapper, ILogger logger, UserManager<UsuarioExterno> userManager, IConfiguration configuration, UsuarioExterno? usuarioExterno)
        {
            _mapper = mapper;
            _logger = logger;
            _userManager = userManager;
            _configuration = configuration;
            _usuarioExterno = usuarioExterno;
        }

        // Públicos

        public async Task<TokenDto> CreateToken(bool populateExp)
        {
            var signingCredentials = GetSigningCredentials();
            var claims = await GetClaims();
            var tokenOptions = GenerateTokenOptions(signingCredentials, claims);

            var refreshToken = GenerateRefreshToken();

            // Verifica se _usuarioExterno é nulo antes de utilizá-lo
            if (_usuarioExterno == null)
            {
                throw new InvalidOperationException("Usuário não está autenticado.");
            }

            await _userManager.UpdateAsync(_usuarioExterno);
            var accessToken = new JwtSecurityTokenHandler().WriteToken(tokenOptions);

            return new TokenDto(accessToken, refreshToken);
        }

        public async Task<IdentityResult> RegisterUser(UserForRegistrationDto userForRegistration)
        {
            var user = _mapper.Map<UsuarioExterno>(userForRegistration);
            var result = await _userManager.CreateAsync(user, userForRegistration.Password);

            if (result.Succeeded)
            {
                _logger.LogInformation("User created a new account with password.");
            }
            else
            {
                foreach (var error in result.Errors)
                {
                    _logger.LogError(error.Description); // Loga os erros
                }
            }

            return result; // Retorna o resultado da criação do usuário
        }

        public async Task<bool> ValidateUser(UserForRegistrationDto userForRegistration)
        {
            var user = await _userManager.FindByEmailAsync(userForRegistration.Username);
            if (user == null) return false;
            var result = await _userManager.CheckPasswordAsync(user, userForRegistration.Password);
            return result;
        }

        // Privados

        private SigningCredentials GetSigningCredentials()
        {
            var key = Encoding.UTF8.GetBytes(Environment.GetEnvironmentVariable("SECRET")); // Obtém a chave do ambiente
            var secretKey = new SymmetricSecurityKey(key); // Cria a chave simétrica
            return new SigningCredentials(secretKey, SecurityAlgorithms.HmacSha256); // Retorna as credenciais de assinatura
        }

        private async Task<List<Claim>> GetClaims()
        {
            if (_usuarioExterno == null)
            {
                throw new InvalidOperationException("Usuário não está autenticado.");
            }

            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.NameIdentifier, _usuarioExterno.Id.ToString()), // ID do usuário
                new Claim(ClaimTypes.Email, _usuarioExterno.Email) // E-mail do usuário
            };

            List<PerfilExterno> listaperfis = _usuarioPerfilExternoService.GetPerfilByUser(_usuarioExterno);

            // Exemplo comentado de como adicionar claims adicionais, se necessário
            /*
            foreach (var perfil in listaperfis)
            {
                claims.Add(new Claim(ClaimTypes.Role, perfil.Nome));

                var permissoes = await _usuarioPerfilExternoService.GetPermissoesByPerfil(perfil.Id);
                foreach (var permissao in permissoes)
                {
                    claims.Add(new Claim("Permissao", permissao.Nome));
                }
            }
            */

            return claims;
        }

        private JwtSecurityToken GenerateTokenOptions(SigningCredentials signingCredentials, List<Claim> claims)
        {
            var jwtSettings = _configuration.GetSection("JwtSettings"); // Obtém configurações do JWT

            var tokenOptions = new JwtSecurityToken(
                issuer: jwtSettings["validIssuer"],
                audience: jwtSettings["validAudience"],
                claims: claims,
                expires: DateTime.Now.AddMinutes(Convert.ToDouble(jwtSettings["expiryMinutes"])), // Define a expiração do token
                signingCredentials: signingCredentials
            );

            return tokenOptions; // Retorna o token JWT
        }

        private string GenerateRefreshToken()
        {
            var randomNumber = new byte[32];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(randomNumber);
                return Convert.ToBase64String(randomNumber);
            }
        }

        private ClaimsPrincipal GetPrincipalFromExpiredToken(string token)
        {
            var jwtSettings = _configuration.GetSection("JwtSettings");
            var tokenValidationParameters = new TokenValidationParameters
            {
                ValidateAudience = true,
                ValidateIssuer = true,
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(Environment.GetEnvironmentVariable("SECRET"))),
                ValidateLifetime = false, // Isso é importante para validar tokens expirados
                ValidIssuer = jwtSettings["validIssuer"],
                ValidAudience = jwtSettings["validAudience"]
            };

            var tokenHandler = new JwtSecurityTokenHandler();
            SecurityToken securityToken;
            var principal = tokenHandler.ValidateToken(token, tokenValidationParameters, out securityToken);
            var jwtSecurityToken = securityToken as JwtSecurityToken;

            if (jwtSecurityToken == null || !jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256, StringComparison.InvariantCultureIgnoreCase))
            {
                throw new SecurityTokenException("Invalid token");
            }

            return principal;
        }
    }
}
