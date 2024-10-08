using AutoMapper;
using Microsoft.Extensions.Logging;
using Rey.Application.Interfaces;
using Rey.Application.ViewModel;
using Rey.Domain.Entities.Auth;
using Rey.Domain.Interfaces.IServices;
using System;
using System.Threading.Tasks;

namespace Rey.Application.AppService
{
    public class AuthAppService : IAuthAppService
    {
        private readonly ITokenService _tokenService;
        private readonly ILogger<AuthAppService> _logger;
        private readonly IMapper _mapper;
        private readonly IUsuarioExternoService _userService;

        public AuthAppService(
            ITokenService tokenService,
            ILogger<AuthAppService> logger,
            IMapper mapper,
            IUsuarioExternoService userService)
        {
            _tokenService = tokenService;
            _logger = logger;
            _mapper = mapper;
            _userService = userService;
        }

        public async Task<TokenViewModel> Login(LoginRequestViewModel request)
        {
            // Aqui assumo que request.UserName está faltando.
            var tokenResponse = await _tokenService.Login(request.UserName, request.Password);

            // Mapear a resposta para TokenViewModel
            return _mapper.Map<TokenViewModel>(tokenResponse);
        }

        public async Task<TokenViewModel> RefreshToken(RefreshTokenRequest request)
        {
            var tokenResponse = await _tokenService.RefreshToken(request.RefreshToken, request.AccessToken);

            // Mapear a resposta para TokenViewModel
            return _mapper.Map<TokenViewModel>(tokenResponse);
        }

        public async Task Register(RegisterViewModel model)
        {
            // Mapeamento do RegisterViewModel para a entidade Registration
            var registration = _mapper.Map<Registration>(model);

            // Chamando o TokenService para registrar o usuário
            await _tokenService.Register(registration);
        }

        public async Task<bool> ForgotPassword(ForgotPasswordViewModel model)
        {
            // Procura o usuário pelo e-mail
            UsuarioExterno user = await _userService.FindUserByEmailAsync(model.Email);
            if (user == null)
            {
                _logger.LogWarning($"Usuário não encontrado para o e-mail: {model.Email}");
                return false; // Usuário não encontrado
            }

            // Gera token de reset de senha
            RefreshToken resetToken = await _userService.GeneratePasswordResetTokenAsync(user);

            // Placeholder para envio de e-mail (futuramente)
            _logger.LogInformation($"Token de reset de senha gerado: {resetToken} para o e-mail: {model.Email}");

            // A implementação do envio de e-mails pode ser adicionada futuramente aqui
            // ex: _emailService.SendPasswordResetEmail(user.Email, resetToken);

            return true;
        }

        public async Task<bool> ResetPassword(ResetPasswordViewModel model)
        {
            // Reset da senha utilizando o token de recuperação e a nova senha
            var result = await _tokenService.ResetPassword(model.Token, model.NovaSenha);
            if (result)
            {
                _logger.LogInformation($"Senha resetada com sucesso para o token: {model.Token}");
            }
            else
            {
                _logger.LogWarning($"Falha ao resetar senha para o token: {model.Token}");
            }
            return result;
        }

        public async Task<bool> VerifyAccount(string token)
        {
            // Verifica o token de verificação de conta
            UsuarioExterno user = await _userService.VerifyAccountTokenAsync(token);
            if (user == null)
            {
                _logger.LogWarning($"Token de verificação inválido: {token}");
                return false; // Token inválido
            }

            // Atualiza o status do usuário para verificado
            bool atualizado = await _userService.UpdateAsync(user);

            _logger.LogInformation($"Conta verificada com sucesso para o token: {token}");
            return atualizado;
        }

        public async Task<bool> Logout(LogoutViewModel model)
        {
            // Revoga o token (acesso e refresh)
            bool success = await _tokenService.RevokeTokens(model.Token);

            if (success)
            {
                _logger.LogInformation($"Logout realizado com sucesso para o token: {model.Token}");
            }
            else
            {
                _logger.LogWarning($"Falha ao realizar logout para o token: {model.Token}");
            }

            return success;
        }
    }
}
