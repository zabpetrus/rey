using Microsoft.AspNetCore.Mvc;
using Rey.Application.Interfaces;
using Rey.Application.ViewModel;
using Rey.Domain.Entities.Auth;
using Rey.Domain.Interfaces.IServices;
using System.Threading.Tasks;

/// <summary>
/// Auth Controller
/// </summary>
[Route("api/auth")]
[ApiController]
public class AuthController : ControllerBase
{
    private readonly IAuthAppService _authAppService;

    public AuthController(IAuthAppService authAppService)
    {
        _authAppService = authAppService;
    }

    /// <summary>
    /// Login
    /// </summary>
    /// <param name="request">Login Request</param>
    /// <returns>A Task of IActionResult.</returns>
    [HttpPost("login")]
    public async Task<IActionResult> Login([FromBody] LoginRequestViewModel request)
    {
        TokenViewModel tokenResponse = await _authAppService.Login(request);
        return Ok(tokenResponse);
    }

    /// <summary>
    /// Refresh Token
    /// </summary>
    /// <param name="request">Refresh Token Request</param>
    /// <returns>A Task of IActionResult.</returns>
    [HttpPost("refresh")]
    public async Task<IActionResult> Refresh([FromBody] RefreshTokenRequest request)
    {
        TokenViewModel tokenResponse = await _authAppService.RefreshToken(request);
        return Ok(tokenResponse);
    }

    /// <summary>
    /// Reset Password
    /// </summary>
    /// <param name="model">Reset Password Model</param>
    /// <returns>A Task of IActionResult.</returns>
    [HttpPost("reset-password")]
    public async Task<IActionResult> ResetPassword([FromBody] ResetPasswordViewModel model)
    {
        bool result = await _authAppService.ResetPassword(model);
        if (result)
        {
            return Ok("Senha redefinida com sucesso.");
        }
        return NotFound("Usuário não encontrado.");
    }

    /// <summary>
    /// Register
    /// </summary>
    /// <param name="model">Register Model</param>
    /// <returns>A Task of IActionResult.</returns>
    [HttpPost("register")]
    public async Task<IActionResult> Register([FromBody] RegisterViewModel model)
    {
        await _authAppService.Register(model);
        return Ok("Usuário registrado com sucesso.");
    }

    /// <summary>
    /// Logout
    /// </summary>
    /// <param name="model">Logout Request Model</param>
    /// <returns>A Task of IActionResult.</returns>
    [HttpPost("logout")]
    public async Task<IActionResult> Logout([FromBody] LogoutViewModel model)
    {
        bool result = await _authAppService.Logout(model);
        if (result)
        {
            return Ok("Logout realizado com sucesso.");
        }
        return BadRequest("Falha ao realizar logout.");
    }

    /// <summary>
    /// Forgot Password (Iniciar recuperação de senha)
    /// </summary>
    /// <param name="model">Forgot Password Request Model</param>
    /// <returns>A Task of IActionResult.</returns>
    [HttpPost("forgot-password")]
    public async Task<IActionResult> ForgotPassword([FromBody] ForgotPasswordViewModel model)
    {
        bool result = await _authAppService.ForgotPassword(model);
        if (result)
        {
            return Ok("Instruções para recuperação de senha enviadas.");
        }
        return BadRequest("Falha ao enviar instruções de recuperação.");
    }

    /// <summary>
    /// Confirmar verificação de conta via token
    /// </summary>
    /// <param name="token">Token de Verificação</param>
    /// <returns>A Task of IActionResult.</returns>
    [HttpGet("verify-account")]
    public async Task<IActionResult> VerifyAccount([FromQuery] string token)
    {
        bool result = await _authAppService.VerifyAccount(token);
        if (result)
        {
            return Ok("Conta verificada com sucesso.");
        }
        return BadRequest("Token de verificação inválido ou expirado.");
    }
}
