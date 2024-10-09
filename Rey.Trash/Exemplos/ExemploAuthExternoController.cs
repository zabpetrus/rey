/*
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.Data;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using Rey.Domain.Entities;
using Rey.Domain.Entities.Auth;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace Rey.Api.Exemplos
{
    /// <summary>
    /// Auth Externo Controller
    /// </summary>
    [Route("api/[controller]")]
    [ApiController]
    public class ExemploAuthExternoController : ControllerBase
    {
        private readonly IHttpContextAccessor _contextAccessor;
        private readonly UserManager<UsuarioExterno> _userManager;
        private readonly RoleManager<PerfilExterno> _roleManager;
        private readonly IConfiguration _configuration;
        private readonly IUsuarioExternoAppService _usuarioExternoAppService;

        public ExemploAuthExternoController(
            IHttpContextAccessor contextAccessor,
            UserManager<UsuarioExterno> userManager,
            RoleManager<PerfilExterno> roleManager,
            IConfiguration configuration,
            IUsuarioExternoAppService usuarioExternoAppService)
        {
            _contextAccessor = contextAccessor;
            _userManager = userManager;
            _roleManager = roleManager;
            _configuration = configuration;
            _usuarioExternoAppService = usuarioExternoAppService;
        }

        /// <summary>
        /// Login
        /// </summary>
        /// <param name="model">LoginModel</param>
        /// <returns>A Task of IActionResult.</returns>
        [HttpPost]
        [Route("login")]
        public async Task<IActionResult> Login([FromBody] LoginRequestViewModel model)
        {
            var user = await _userManager.FindByNameAsync(model.UserName);

            if (user != null && await _userManager.CheckPasswordAsync(user, model.Password))
            {
                var userRoles = await _userManager.GetRolesAsync(user);
                var authClaims = new List<Claim>
                {
                    new Claim(ClaimTypes.Name, user.NomeDeUsuario),
                    new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
                };

                foreach (var userRole in userRoles)
                {
                    authClaims.Add(new Claim(ClaimTypes.Role, userRole));
                }

                var token = CreateToken(authClaims);
                var refreshToken = GenerateRefreshToken();

                // Set refresh token expiration
                int refreshTokenValidityInMinutes = int.TryParse(_configuration["JWT:RefreshTokenValidityInMinutes"], out int result) ? result : 60;

                user.RefreshToken = refreshToken;
                user.RefreshTokenExpiryTime = DateTime.Now.AddMinutes(refreshTokenValidityInMinutes);

                await _userManager.UpdateAsync(user);

                return Ok(new
                {
                    Token = new JwtSecurityTokenHandler().WriteToken(token),
                    RefreshToken = refreshToken,
                    Expiration = token.ValidTo
                });
            }
            return Unauthorized();
        }

        /// <summary>
        /// Register User with Roles
        /// </summary>
        /// <param name="model">UsuarioExternoViewModel</param>
        /// <returns>A Task of IActionResult.</returns>
        [HttpPost]
        [Route("register")]
        public async Task<IActionResult> Register([FromBody] UsuarioExternoViewModel model)
        {
            var userExists = await _userManager.FindByNameAsync(model.NomeDeUsuario);

            if (userExists != null)
            {
                return StatusCode(StatusCodes.Status500InternalServerError,
                    new { Status = "Error", Message = "User already exists!" });
            }

            UsuarioExterno user = new()
            {
                Email = model.Email,
                NomeDeUsuario = model.NomeDeUsuario,
                Cpf = model.Cpf,
                RefreshToken = model.RefreshToken,
            };

            var result = await _userManager.CreateAsync(user, model.HashSenha);

            if (!result.Succeeded)
            {
                return StatusCode(StatusCodes.Status500InternalServerError,
                       new { Status = "Error", Message = "User creation failed." });
            }

            // Atribuindo os papéis ao usuário de forma dinâmica
            var rolesToAssign = new List<PerfilExterno>();
            foreach (var role in rolesToAssign)
            {
                if (!await _roleManager.RoleExistsAsync(role.Nome))
                {
                    await _roleManager.CreateAsync(new PerfilExterno { Nome = role.Nome });
                }

                await _userManager.AddToRoleAsync(user, role.Nome);
            }

            return Ok(new { Status = "Success", Message = "User created successfully!" });
        }

        /// <summary>
        /// Refresh Token
        /// </summary>
        /// <param name="tokenModel">TokenViewModel</param>
        /// <returns>A Task of IActionResult.</returns>
        [HttpPost]
        [Route("refresh-token")]
        public async Task<IActionResult> RefreshToken(TokenViewModel tokenModel)
        {
            if (tokenModel == null)
            {
                return BadRequest("Invalid client request");
            }

            string? accessToken = tokenModel.AccessToken;
            string? refreshToken = tokenModel.RefreshToken;

            var principal = GetPrincipalFromExpiredToken(accessToken);
            if (principal == null)
            {
                return BadRequest("Invalid access token/refresh token");
            }

            string username = principal.Identity.Name;
            var user = await _userManager.FindByNameAsync(username);

            if (user == null || user.RefreshToken != refreshToken ||
                       user.RefreshTokenExpiryTime <= DateTime.Now)
            {
                return BadRequest("Invalid access token/refresh token");
            }

            var newAccessToken = CreateToken(principal.Claims.ToList());
            var newRefreshToken = GenerateRefreshToken();

            user.RefreshToken = newRefreshToken;
            await _userManager.UpdateAsync(user);

            return new ObjectResult(new
            {
                accessToken = new JwtSecurityTokenHandler().WriteToken(newAccessToken),
                refreshToken = newRefreshToken
            });
        }

        /// <summary>
        /// Revoke Refresh Token
        /// </summary>
        /// <param name="username">Username</param>
        /// <returns>A Task of IActionResult.</returns>
        [Authorize]
        [HttpPost]
        [Route("revoke/{username}")]
        public async Task<IActionResult> Revoke(string username)
        {
            var user = await _userManager.FindByNameAsync(username);
            if (user == null) return BadRequest("Invalid user name");

            user.RefreshToken = null;
            await _userManager.UpdateAsync(user);

            return NoContent();
        }

        /// <summary>
        /// Revoke All Refresh Tokens
        /// </summary>
        /// <returns>A Task of IActionResult.</returns>
        [Authorize]
        [HttpPost]
        [Route("revoke-all")]
        public async Task<IActionResult> RevokeAll()
        {
            var users = _userManager.Users.ToList();
            foreach (var user in users)
            {
                user.RefreshToken = null;
                await _userManager.UpdateAsync(user);
            }

            return NoContent();
        }

        private JwtSecurityToken CreateToken(List<Claim> authClaims)
        {
            var authSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JWT:SecretKey"]));
            int tokenValidityInMinutes = int.TryParse(_configuration["JWT:TokenValidityInMinutes"], out var result) ? result : 60;

            var token = new JwtSecurityToken(
                issuer: _configuration["JWT:ValidIssuer"],
                audience: _configuration["JWT:ValidAudience"],
                expires: DateTime.Now.AddMinutes(tokenValidityInMinutes),
                claims: authClaims,
                signingCredentials: new SigningCredentials(authSigningKey, SecurityAlgorithms.HmacSha256)
            );

            return token;
        }

        private static string GenerateRefreshToken()
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
            var tokenHandler = new JwtSecurityTokenHandler();
            var validationParameters = new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidateAudience = true,
                ValidateLifetime = false, // don't validate the expiration
                ValidateIssuerSigningKey = true,
                ValidIssuer = _configuration["JWT:ValidIssuer"],
                ValidAudience = _configuration["JWT:ValidAudience"],
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JWT:SecretKey"]))
            };

            return tokenHandler.ValidateToken(token, validationParameters, out _);
        }
    }
}
    */