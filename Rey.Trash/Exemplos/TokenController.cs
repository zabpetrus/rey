/*
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

using Rey.Domain.Entities.Auth;
using Rey.Domain.Interfaces.IServices;

namespace Rey.Api.Exemplos
{
    /// <summary>
    /// Token Controller
    /// </summary>
    [Route("api/[controller]")]
    [ApiController]
    public class TokenController : ControllerBase
    {
        private readonly IAuthenticatorService _authenticationService;
        private readonly ITokenService _tokenService;

        public TokenController(IAuthenticatorService authenticationService, ITokenService tokenService)
        {
            _authenticationService = authenticationService;
            _tokenService = tokenService;
        }

        /// <summary>
        /// Refreshes the access token using the provided refresh token.
        /// </summary>
        /// <param name="tokenApiModel">A Token Api Model containing access and refresh tokens.</param>
        /// <returns>An IActionResult with the new tokens or an error response.</returns>
        [HttpPost("refresh")]
        public IActionResult Refresh([FromBody] TokenApiModel tokenApiModel)
        {
            if (tokenApiModel == null)
                return BadRequest("Invalid client request");

            var accessToken = tokenApiModel.AccessToken;
            var refreshToken = tokenApiModel.RefreshToken;

            var principal = _tokenService.GetPrincipalFromExpiredToken(accessToken);

            if (principal?.Identity.IsAuthenticated ?? false)
            {
                var username = principal.Identity.Name;
                var result = _authenticationService.RefreshToken(accessToken, refreshToken, username);
                return Ok(result);
            }

            return Unauthorized("Invalid token");
        }

        /// <summary>
        /// Revokes the current user's refresh token.
        /// </summary>
        /// <returns>An IActionResult indicating success or failure.</returns>
        [HttpPost("revoke")]
        [Authorize]
        public IActionResult Revoke()
        {
            var username = User.Identity.Name;

            if (string.IsNullOrEmpty(username))
            {
                return BadRequest("Invalid client request");
            }

            var userRevoked = _authenticationService.RevokeToken(username);
            if (userRevoked == null)
            {
                return BadRequest("Unable to revoke token");
            }
            return NoContent();
        }
    }
}
             */