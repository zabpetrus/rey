using Rey.Domain.Entities;
using Rey.Domain.Entities.Auth;
using Rey.Domain.Interfaces.IRepository;
using Rey.Domain.Interfaces.IServices;
using Rey.Trash.Dto;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace Rey.Trash.Services
{
    public class AuthService : IAuthService
    {
        private readonly ITokenService _tokenService;
        private readonly IUsuarioExternoRepository _usuarioExternoRepository;
        private readonly IPermissaoExternoRepository _permissaoExternoRepository;

        public AuthService(ITokenService tokenService, IUsuarioExternoRepository usuarioExternoRepository, IPermissaoExternoRepository permissaoExternoRepository)
        {
            _tokenService = tokenService;
            _usuarioExternoRepository = usuarioExternoRepository;
            _permissaoExternoRepository = permissaoExternoRepository;
        }

        public async Task<Token> Login(LoginRequestViewModel loginRequestModel)
        {

            var usuario = _usuarioExternoRepository.FindByCpf(loginRequestModel.UserName) ??
                          _usuarioExternoRepository.FindByEmail(loginRequestModel.UserName);


            if (usuario == null || !usuario.VerificarSenha(loginRequestModel.Password))
            {
                throw new Exception("Credenciais inválidas");
            }


            // Consultando os perfis do usuário via banco
            List<PerfilExterno> perfis = _usuarioExternoRepository.GetPerfilByUser(usuario);

            // Consultando permissões dos perfis e transformando em Claims
            List<Claim> claims = new List<Claim>();
            foreach (var perfil in perfis)
            {
                List<PermissaoExterno> permissoes = _permissaoExternoRepository.RetrievePermissionsByProfile(perfil);
                foreach (var permissao in permissoes)
                {
                    claims.Add(new Claim(ClaimTypes.Role, permissao.Nome));
                }
            }

            // Token com as Claims
            Token token = _tokenService.GerarTokenJwtByClaims(claims);
            return token;
        }
    }





}
