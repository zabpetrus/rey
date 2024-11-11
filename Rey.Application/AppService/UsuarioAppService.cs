using AutoMapper;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Rey.Application.Interfaces;
using Rey.Application.ViewModel;
using Rey.Domain.Entities;
using Rey.Domain.Entities._Abstract;
using Rey.Domain.Entities.Auth;
using Rey.Domain.Interfaces.IServices;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace Rey.Application.AppService
{
    public class UsuarioAppService : IUsuarioAppService
    {
        private readonly IUsuarioExternoService _usuarioExternoService;
        private readonly IPerfilExternoService _perfilExternoService;
        private readonly IPermissaoExternoService _permissaoExternoService;
        private readonly IHttpContextAccessor _httpContextAccessor;
        private readonly ITokenService _tokenService;
        private readonly IRefreshTokenService _refreshTokenExternoService ;
        private readonly IMapper _mapper;
        private readonly ILogger<UsuarioAppService> _logger;

        public UsuarioAppService(IUsuarioExternoService usuarioExternoService, IPerfilExternoService perfilExternoService, IPermissaoExternoService permissaoExternoService, IHttpContextAccessor httpContextAccessor, ITokenService tokenService, IRefreshTokenService refreshTokenExternoService, IMapper mapper, ILogger<UsuarioAppService> logger)
        {
            _usuarioExternoService = usuarioExternoService;
            _perfilExternoService = perfilExternoService;
            _permissaoExternoService = permissaoExternoService;
            _httpContextAccessor = httpContextAccessor;
            _tokenService = tokenService;
            _refreshTokenExternoService = refreshTokenExternoService;
            _mapper = mapper;
            _logger = logger;
        }

      
        public async Task<UsuarioViewModel> CreateAndGetAsync(UsuarioViewModel usuarioExternoViewModel)
        {
            try
            {
                // Mapeia o ViewModel para o modelo de domínio
                Usuario usuario = _mapper.Map<Usuario>(usuarioExternoViewModel);

                usuario.ConfigurarSenha(usuarioExternoViewModel.Senha);

                // Cria o usuário no banco de dados
                Usuario usuarioCriado = await _usuarioExternoService.CreateAsync(usuario);

                return _mapper.Map<UsuarioViewModel>(usuarioCriado);

            }
            catch (Exception ex)
            {
                // Se ocorrer uma exceção, lança a exceção original para manter a stack trace
                throw new Exception("Erro ao criar usuário e refresh token.", ex);
            }
        }

        public async Task<bool> CreateUserProfile(UsuarioPerfilViewModel request)
        {
            try
            {
                // Recupera o usuário e o perfil pelo ID
                Usuario usuario = await _usuarioExternoService.GetByIdAsync(request.UsuarioId);
                Domain.Entities.Perfil perfil = await _perfilExternoService.GetByIdAsync(request.PerfilId);

                // Verifica se o usuário ou o perfil são nulos
                if (usuario == null)
                {
                    _logger.LogWarning($"Usuário com ID {request.UsuarioId} não encontrado.");
                    return false;
                }

                if (perfil == null)
                {
                    _logger.LogWarning($"Perfil com ID {request.PerfilId} não encontrado.");
                    return false;
                }

                // Registrar o perfil para o usuário
                bool resultado = await _usuarioExternoService.RegistrarPerfil(usuario.Id, perfil.Id);

                if (resultado)
                {
                    _logger.LogInformation($"Perfil {perfil.Id} associado ao usuário {usuario.Id} com sucesso.");
                }
                else
                {
                    _logger.LogWarning($"Falha ao associar o perfil {perfil.Id} ao usuário {usuario.Id}.");
                }

                return resultado;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Erro ao criar perfil de usuário.");
                return false;
            }
        }


        public async Task<bool> DeleteById(long id)
        {
            try
            {
                // Obter o refresh token associado ao usuário
                var userToken = _refreshTokenExternoService.GetByUserId(id);

                // Verificar se o usuário existe e se a remoção foi bem-sucedida
                bool response =  _usuarioExternoService.DeleteById(id);

                if (response)
                {
                    // Se o usuário foi excluído com sucesso, remover o refresh token
                    if (userToken != null)
                    {
                        _refreshTokenExternoService.RemoveRefreshToken(userToken.Token);
                    }
                    return true; // Usuário e tokens excluídos com sucesso
                }
                return false; // Falha ao excluir o usuário
            }
            catch (Exception ex)
            {
                // Tratar exceções, se necessário
                // Você pode registrar o erro ou lançar uma exceção personalizada
                throw new Exception("Erro ao excluir o usuário e seus tokens.", ex);
            }
        }


        public UsuarioViewModel FindUserByCpf(string cpf)
        {
            var res = _usuarioExternoService.FindUserByCpf(cpf);
            return _mapper.Map<UsuarioViewModel>(res);
        }


        public async Task<List<UsuarioViewModel>> GetAll()
        {
            try
            {
                List<Usuario> usuarios = _usuarioExternoService.GetAll();
                return _mapper.Map<List<UsuarioViewModel>>(usuarios);
            }
            catch (Exception ex)
            {
                throw new Exception("Erro ao obter a lista de usuários.", ex);
            }
        }

        public UsuarioViewModel GetById(long id)
        {
            try
            {
                var usuario = _usuarioExternoService.GetById(id);
                return usuario == null ? null : _mapper.Map<UsuarioViewModel>(usuario);
            }
            catch (Exception ex)
            {
                throw new Exception($"Erro ao obter o usuário com ID {id}.", ex);
            }
        }

        public async Task<bool> Update(UsuarioViewModel usuarioExternoViewModel)
        {
            try
            {
                var usuario = _mapper.Map<Usuario>(usuarioExternoViewModel);
                return _usuarioExternoService.Update(usuario);
            }
            catch (Exception ex)
            {
                throw new Exception("Erro ao atualizar o usuário.", ex);
            }
        }

    }
}
