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
    public class UsuarioExternoAppService : IUsuarioExternoAppService
    {
        private readonly IUsuarioExternoService _usuarioExternoService;
        private readonly IPerfilExternoService _perfilExternoService;
        private readonly IPermissaoExternoService _permissaoExternoService;
        private readonly IHttpContextAccessor _httpContextAccessor;
        private readonly ITokenService _tokenService;
        private readonly IRefreshTokenExternoService _refreshTokenExternoService ;
        private readonly IMapper _mapper;
        private readonly ILogger<UsuarioExternoAppService> _logger;

        public UsuarioExternoAppService(IUsuarioExternoService usuarioExternoService, IPerfilExternoService perfilExternoService, IPermissaoExternoService permissaoExternoService, IHttpContextAccessor httpContextAccessor, ITokenService tokenService, IRefreshTokenExternoService refreshTokenExternoService, IMapper mapper, ILogger<UsuarioExternoAppService> logger)
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

      
        public async Task<UsuarioExternoAuthViewModel> CreateAndGetAsync(UsuarioExternoViewModel permissaoExternaViewModel)
        {
            try
            {
                // Mapeia o ViewModel para o modelo de domínio
                UsuarioExterno usuario = _mapper.Map<UsuarioExterno>(permissaoExternaViewModel);

                // Cria o usuário no banco de dados
                UsuarioExterno usuarioCriado = await _usuarioExternoService.CreateAsync(usuario);

                // Obtém os perfis (Roles) relacionados ao usuário
                List<PerfilExterno> perfis = _usuarioExternoService.FetchUserProfilesByUserId(usuarioCriado.Id);

                // Obtém as permissões (Claims) associadas aos perfis do usuário (se existirem perfis)
                List<PermissaoExterno> permissoes = perfis.Any()
                    ? _usuarioExternoService.GetUserPermissionsByProfileIds(perfis.Select(p => p.Id).ToList())
                    : new List<PermissaoExterno>(); // Lista vazia se não houver perfis

                // Cria as claims do JWT com base nas permissões e informações do usuário
                var claims = new List<Claim>
                {
                    new Claim(ClaimTypes.Name, usuarioCriado.Nome),
                    new Claim(ClaimTypes.NameIdentifier, usuarioCriado.Id.ToString()),
                    new Claim(ClaimTypes.Email, usuarioCriado.Email)
                };

                // Adicionar as permissões (Claims) personalizadas
                if (permissoes.Any())
                {
                    foreach (PermissaoExterno permissao in permissoes)
                    {
                        if (!string.IsNullOrEmpty(permissao.Nome)) // Verifica se o código não é nulo ou vazio
                        {
                            claims.Add(new Claim("Permissao", permissao.Nome)); // Claims personalizadas para permissões
                        }
                    }
                }

                // Adicionar os perfis (Roles) como claims de role
                if (perfis != null && perfis.Any())
                {
                    foreach (PerfilExterno perfil in perfis)
                    {
                        // Certifique-se de que perfil.Codigo seja uma string
                        if (!string.IsNullOrEmpty(perfil.Codigo))
                        {
                            claims.Add(new Claim(ClaimTypes.Role, perfil.Codigo)); // Claims para perfis (Roles)
                        }
                    }
                }
                // Gera o AccessToken JWT
                Token jwtToken = _tokenService.GerarTokenJwtByClaims(claims);

                // Cria a entidade RefreshToken com os dados do token gerado
                RefreshToken refreshToken = new RefreshToken
                {
                    Token = jwtToken.RefreshToken,  // Utiliza o RefreshToken gerado
                    Created = DateTime.UtcNow,
                    Expires = jwtToken.RefreshTokenExpiration,
                    CreatedByIp = _httpContextAccessor.HttpContext?.Connection.RemoteIpAddress?.ToString() ?? "IP não disponível",
                    UsuarioId = usuarioCriado.Id
                };

                // Salva o refresh token no banco de dados
                await _refreshTokenExternoService.CreateAsync(refreshToken);

                // Prepara o retorno no formato de UsuarioExternoAuthViewModel com tokens
                var usuarioAuthViewModel = _mapper.Map<UsuarioExternoAuthViewModel>(usuarioCriado);
                usuarioAuthViewModel.AccessToken = jwtToken.AccessToken;
                usuarioAuthViewModel.RefreshToken = jwtToken.RefreshToken;

                return usuarioAuthViewModel; // Retorna o usuário com os tokens
            }
            catch (Exception ex)
            {
                // Se ocorrer uma exceção, lança a exceção original para manter a stack trace
                throw new Exception("Erro ao criar usuário e refresh token.", ex);
            }
        }




        public async Task<bool> DeleteById(long id)
        {
            try
            {
                // Obter o refresh token associado ao usuário
                var userToken = await _refreshTokenExternoService.GetByUserIdAsync(id);

                // Verificar se o usuário existe e se a remoção foi bem-sucedida
                bool response =  _usuarioExternoService.DeleteById(id);

                if (response)
                {
                    // Se o usuário foi excluído com sucesso, remover o refresh token
                    if (userToken != null)
                    {
                        await _refreshTokenExternoService.RemoveRefreshTokenAsync(userToken.Token);
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


        public UsuarioExternoViewModel FindUserByCpf(string cpf)
        {
            var res = _usuarioExternoService.FindUserByCpf(cpf);
            return _mapper.Map<UsuarioExternoViewModel>(res);
        }


        public async Task<List<UsuarioExternoViewModel>> GetAll()
        {
            try
            {
                List<UsuarioExterno> usuarios = _usuarioExternoService.GetAll();
                return _mapper.Map<List<UsuarioExternoViewModel>>(usuarios);
            }
            catch (Exception ex)
            {
                throw new Exception("Erro ao obter a lista de usuários.", ex);
            }
        }

        public UsuarioExternoViewModel GetById(long id)
        {
            try
            {
                var usuario = _usuarioExternoService.GetById(id);
                return usuario == null ? null : _mapper.Map<UsuarioExternoViewModel>(usuario);
            }
            catch (Exception ex)
            {
                throw new Exception($"Erro ao obter o usuário com ID {id}.", ex);
            }
        }

        public async Task<bool> Update(UsuarioExternoViewModel usuarioExternoViewModel)
        {
            try
            {
                var usuario = _mapper.Map<UsuarioExterno>(usuarioExternoViewModel);
                return _usuarioExternoService.Update(usuario);
            }
            catch (Exception ex)
            {
                throw new Exception("Erro ao atualizar o usuário.", ex);
            }
        }

    }
}
