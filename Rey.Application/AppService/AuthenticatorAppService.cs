using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Threading.Tasks;
using Rey.Domain.Entities.Auth;
using Rey.Domain.Interfaces.IServices;
using Rey.Domain.Interfaces.IRepository;
using Microsoft.IdentityModel.Tokens;
using Rey.Application.Interfaces;
using Rey.Application.ViewModel;
using Rey.Domain.Entities.Dto;
using Rey.Domain.Enums;
using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Configuration;
using AutoMapper;

public class AuthenticatorAppService : IAuthenticatorAppService
{
    private readonly ITokenService _tokenService;
    private readonly IUsuarioExternoService _usuarioExternoService;
    private readonly IRefreshTokenRepository _refreshTokenRepository;
    private readonly IHttpContextAccessor _httpContextAccessor;
    private readonly ILogger<AuthenticatorAppService> _logger;
    private readonly IConfiguration _configuration;
    private readonly IRefreshTokenService _refreshTokenService;
    private readonly IMapper _mapper;

    public AuthenticatorAppService(ITokenService tokenService, IUsuarioExternoService usuarioExternoService, IRefreshTokenRepository refreshTokenRepository, IHttpContextAccessor httpContextAccessor, ILogger<AuthenticatorAppService> logger, IConfiguration configuration, IRefreshTokenService refreshTokenService, IMapper mapper)
    {
        _tokenService = tokenService;
        _usuarioExternoService = usuarioExternoService;
        _refreshTokenRepository = refreshTokenRepository;
        _httpContextAccessor = httpContextAccessor;
        _logger = logger;
        _configuration = configuration;
        _refreshTokenService = refreshTokenService;
        _mapper = mapper;
    }







    // Método para gerar um novo AccessToken a partir de um RefreshToken
    public RefreshToken RefreshToken(string accessToken, string refreshToken, string? username)
    {
        // Validar o token de acesso (acessToken) expirado e obter as claims dele
        ClaimsPrincipal principal = _tokenService.GetPrincipalFromExpiredToken(accessToken);

        if (principal == null)
        {
            throw new SecurityTokenException("Token de acesso inválido.");
        }

        // Validar o refresh token no banco de dados
        var storedRefreshToken = _refreshTokenRepository.CreateRefreshToken(refreshToken);
        if (storedRefreshToken == null || storedRefreshToken.IsExpired || storedRefreshToken.IsRevoked)
        {
            throw new SecurityTokenException("Refresh token inválido ou expirado.");
        }

        // Obter o usuário associado ao refresh token
        Usuario usuario = _usuarioExternoService.GetByIdAsync(storedRefreshToken.UsuarioId).Result;
        if (usuario == null || (username != null && usuario.Nome != username))
        {
            throw new SecurityTokenException("Usuário associado ao token não encontrado.");
        }

        // Gerar um novo token JWT (AccessToken)
        var claims = new List<Claim>
        {
            new Claim(ClaimTypes.Name, usuario.Nome)
        };

        // Adicionar os perfis de usuário como roles
        var perfisDeUsuario = _usuarioExternoService.FetchUserProfilesByUserId(usuario.Id);
        foreach (var perfil in perfisDeUsuario)
        {
            claims.Add(new Claim(ClaimTypes.Role, perfil.Codigo));
        }

        // Gerar novo AccessToken
        var newJwtToken = _tokenService.GerarTokenJwtByClaims(claims);

        // Atualizar o refresh token ou criar um novo se necessário
        var newRefreshToken = _tokenService.GenerateRefreshToken();
        storedRefreshToken.Token = newRefreshToken;
        storedRefreshToken.Expires = DateTime.Now.AddDays(7);
        storedRefreshToken.Created = DateTime.Now;

        _refreshTokenRepository.Update(storedRefreshToken);  // Atualizar o refresh token no banco

        return storedRefreshToken;
    }

    public string GenerateRefreshToken()
    {
        var randomNumber = new byte[64];
        using (var rng = RandomNumberGenerator.Create())
        {
            rng.GetBytes(randomNumber);
            return Convert.ToBase64String(randomNumber);
        }
    }


    public string GenerateToken(List<Claim> userClaims)
    {
        // Obtendo a chave secreta do JWT a partir das configurações
        string secretKey = _configuration["Auth:SecretKey"];

        if (string.IsNullOrWhiteSpace(secretKey))
        {
            throw new InvalidOperationException("A chave secreta não pode estar vazia.");
        }

        // Convertendo a chave secreta para um array de bytes
        byte[] secretKeyBytes = Encoding.UTF8.GetBytes(secretKey);

        // Criando a chave de segurança simétrica
        SymmetricSecurityKey signingKey = new SymmetricSecurityKey(secretKeyBytes);

        // Obtendo a validade do token a partir das configurações
        if (!int.TryParse(_configuration["JWTSettings:AccessTokenExpirationInMinutes"], out int tokenValidityInMinutes))
        {
            throw new InvalidOperationException("A validade do token é inválida.");
        }

        var expirationMinutes = int.Parse(_configuration["JWTSettings:AccessTokenExpirationInMinutes"]);

        // Criando o token JWT
        JwtSecurityToken jwtToken = new JwtSecurityToken(

            issuer: _configuration["JWTSettings:ValidIssuer"],
            audience: _configuration["JWTSettings:ValidAudience"],
            expires: DateTime.UtcNow.AddMinutes(expirationMinutes),
            claims: userClaims,
            signingCredentials: new SigningCredentials(signingKey, SecurityAlgorithms.HmacSha256)

        );

        // Retornando o token como string
        var tresult = new JwtSecurityTokenHandler()
            .WriteToken(jwtToken).ToString();

        return tresult;
    }



    public TokenResult RenovarToken(string refreshToken, List<Claim> claims)
    {
        // Verificar se o Refresh Token ainda é válido
        RefreshToken tokenNoBanco = _tokenService.GetByToken(refreshToken);

        if (tokenNoBanco == null || tokenNoBanco.Expires < DateTime.UtcNow)
        {
            throw new SecurityTokenException("Refresh token inválido ou expirado.");
        }

        // Gerar um novo Access Token
        string novoAccessToken = _tokenService.GerarJwt();

        // Atualizar o Refresh Token se necessário (caso ele esteja próximo da expiração)
        if (tokenNoBanco.Expires < DateTime.UtcNow.AddDays(1))
        {
            var novoRefreshToken = GenerateRefreshToken();
            tokenNoBanco.Token = novoRefreshToken;
            tokenNoBanco.Expires = DateTime.UtcNow.AddDays(7);

            //Atualizar o Token no banco
            _refreshTokenRepository.Update(tokenNoBanco);
        }

        return new TokenResult
        {
            AccessToken = novoAccessToken,
            RefreshToken = tokenNoBanco.Token,
            AccessTokenExpiration = DateTime.UtcNow.AddMinutes(7),
            RefreshTokenExpiration = tokenNoBanco.Expires
        };
    }

   

    private RevokeToken ResolveRevokedIpUser(Usuario usuario)
    {
        // Busca o refresh token associado
        RefreshToken refreshToken = _refreshTokenRepository.GetRefreshTokenByToken(usuario);

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
                NewToken = refreshToken.ReplacedByToken
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
            _refreshTokenService.Update(refreshToken);

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

            _refreshTokenService.Update(refreshToken);

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



    public bool ResetPassword(string token, string novasenha)
    {
        // Validar o token de reset de senha e procurar o usuário correspondente

        _logger.LogInformation("Iniciando processo de redefinição de senha.");


        Usuario usuario = _usuarioExternoService.GetByResetPasswordToken(token);

        if (usuario == null || string.IsNullOrEmpty(novasenha))
        {
            _logger.LogWarning("Token inválido ou expirado para redefinição de senha.");
            return false;
        }

        // Redefinir a senha (criptografar a nova senha antes de armazenar)
        usuario.RedefinirSenha(novasenha);
        _usuarioExternoService.Update(usuario);
        return true;

    }

    public Usuario Register(Registration registration)
    {

        Usuario usuarioExistente = _usuarioExternoService.FindUserByCpf(registration.Cpf) ??
            _usuarioExternoService.FindUserByEmail(registration.Email);


        if (usuarioExistente != null)
        {
            throw new InvalidOperationException("Este usuário já está registrado.");
        }

        Usuario novo = _mapper.Map<Usuario>(registration);

        novo.VerificarSenha(registration.HashSenha);

        Usuario criado = _usuarioExternoService.CreateAndGet(novo);  // Salvar o novo usuário no banco

        return criado;
    }

    public bool RevogarTodosTokens(string username, TipoUsuario tipoUsuario)
    {
        // Declarando uma variável para armazenar o usuário
        object usuario = null;

        // Buscar o usuário no banco de dados de acordo com o tipo de usuário
        if (tipoUsuario == TipoUsuario.Externo)
        {
            usuario = _usuarioExternoService.FindUserByCpf(username) ??
                      _usuarioExternoService.FindUserByEmail(username) ??
                      _usuarioExternoService.FindByUsername(username);
        }
  
        // Se o usuário não foi encontrado, retornar false
        if (usuario == null)
        {
            return false; // Usuário não encontrado
        }

        // Identificando o ID do usuário, independente do tipo
        long usuarioId;

        if (usuario is Usuario externo)
        {
            usuarioId = externo.Id; // Atribuindo o ID do usuário externo
        }
        else
        {
            return false; // Tipo de usuário inválido
        }

        // Buscar todos os tokens de refresh associados ao usuário
        List<RefreshToken> tokens = _tokenService.GetRefreshTokenByUsuarioId(usuarioId);
        if (tokens == null || !tokens.Any())
        {
            return false; // Não há tokens para este usuário
        }

        // Remover todos os tokens do banco de dados
        foreach (var token in tokens)
        {
            _tokenService.DeleteById(token.Id);
        }

        return true; // Tokens revogados com sucesso
    }



    public bool RevokeTokens(string token)
    {
        try
        {
            // Verifica se o Refresh Token existe no banco de dados
            RefreshToken refreshToken = _tokenService.GetRefreshToken(token);

            if (refreshToken == null)
            {
                _logger.LogWarning($"Tentativa de revogar um token inexistente: {token}");
                return false; // Token não encontrado
            }

            // Revogar o token removendo-o do banco de dados
            bool revoked = _tokenService.RemoveRefreshToken(refreshToken);

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


    public bool ValidateToken(string token, Usuario externo)
    {
        // Verifica se o token é nulo ou vazio
        if (string.IsNullOrWhiteSpace(token))
        {
            return false; // Token inválido
        }


        RefreshToken? refreshToken = _tokenService.GetByToken(token);


        if (refreshToken == null)
        {
            return false;
        }

        // Verifica se o token pertence ao usuário correto
        if (refreshToken.UsuarioId != externo.Id)
        {
            return false; // Token não pertence ao usuário
        }

        // Verifica se o token está expirado
        if (refreshToken.Expires < DateTime.UtcNow)
        {
            return false; // Token expirado
        }

        // Se todas as validações passarem, o token é válido
        return true;
    }





    public TokenResult LoginExterno(string username, string password)
    {
        try
        {
            // Busca pelo usuário com base no CPF, email ou nome de usuário
            Usuario usuario =
                _usuarioExternoService.FindUserByCpf(username) ??
                _usuarioExternoService.FindUserByEmail(username) ??
                _usuarioExternoService.FindByUsername(username);

            // Verifica se o usuário foi encontrado
            if (usuario == null)
            {
                _logger.LogWarning("Usuário não encontrado para o username: {Username}", username);
                return new TokenResult
                {
                    Error = "Erro na recuperação de usuário."
                };
            }

            // Verifica se a senha está correta
            if (!usuario.VerificarSenha(password))
            {

                _logger.LogWarning("Senha incorreta para o usuário: {Username}", username);
                return new TokenResult { Error = "Senha Incorreta" };
            }

            var authClaims = new List<Claim>
                {
                    new Claim(JwtRegisteredClaimNames.Sub, usuario.Nome),
                    new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                    new Claim(JwtRegisteredClaimNames.NameId, usuario.Id.ToString()),
                    new Claim(ClaimTypes.NameIdentifier, usuario.Id.ToString()),
                    new Claim(ClaimTypes.Name, usuario.Nome),
                    new Claim(ClaimTypes.Role, "admin")
                };


            string accessToken = GenerateToken(authClaims);

            string refreshToken = GenerateRefreshToken();

            // Obter IP do cliente e do servidor
            string createdByIp = _httpContextAccessor.HttpContext?.Connection?.RemoteIpAddress?.ToString();
            string serverIp = Dns.GetHostAddresses(Dns.GetHostName()).FirstOrDefault()?.ToString();

            int refreshTokenValidityInDays = int.Parse(_configuration["JWTSettings:RefreshTokenExpirationInDays"]);

            // Verificação dos valores gerados
            if (string.IsNullOrEmpty(accessToken) || string.IsNullOrEmpty(refreshToken) ||
                string.IsNullOrEmpty(createdByIp) || string.IsNullOrEmpty(serverIp) || refreshTokenValidityInDays <= 0)
            {
                _logger.LogError("Falha na geração do token ou obtenção dos IPs.");
                return new TokenResult { Error = "Falha na geração do token ou obtenção dos IPs." };
            }

            RevokeToken revokeToken = ValidateToken(accessToken, authClaims, createdByIp, serverIp);

            // Criação do refresh token
            RefreshToken refresh = new()
            {
                Token = refreshToken,
                Expires = DateTime.UtcNow.AddDays(refreshTokenValidityInDays),
                Created = DateTime.UtcNow,
                CreatedByIp = createdByIp,
                Revoked = revokeToken.Revoked,
                RevokedByIp = serverIp,
                ReasonRevoked = revokeToken.ReasonRevoked,
                ReplacedByToken = revokeToken.NewToken,
                UsuarioId = usuario.Id,
                TipoUsuario = TipoUsuario.Externo,

            };

            RefreshToken response = _tokenService.CreateAndGet(refresh);

            if (response == null)
            {
                return new TokenResult { Error = "Ops! Não foi possível gravar no banco de dados" };
            }

            // Montando a resposta do token
            TokenResult tokenViewModel = new TokenResult
            {
                AccessToken = accessToken,
                RefreshToken = refreshToken,
                AccessTokenExpiration = DateTime.UtcNow.AddMinutes(int.Parse(_configuration["JWTSettings:AccessTokenExpirationInMinutes"])),
                RefreshTokenExpiration = DateTime.UtcNow.AddDays(refreshTokenValidityInDays)
            };

            return tokenViewModel;
        }
        catch (Exception ex)
        {
            _logger.LogError("Erro ao realizar login externo: " + ex);
            return new TokenResult { Error = "Ops! Erro" + ex };
        }
    }

    private string? ReplacedByTokenGenerator(Usuario externo)
    {
        // Encontrando os tokens do Usuário
        List<RefreshToken> refreshTokens = _tokenService.FindTokensByUser(externo);

        // Se não houver tokens, retorna null
        if (refreshTokens == null || !refreshTokens.Any())
        {
            return null;
        }

        // Encontra o token mais recente com base na data de criação (Created)
        RefreshToken? mostRecentToken = refreshTokens
            .OrderByDescending(rt => rt.Created)
            .FirstOrDefault();

        // Retorna o token mais recente ou null se não houver tokens
        return mostRecentToken?.Token; // Supondo que mostRecentToken.Token seja string, o ToString() não é necessário
    }


    private RevokeToken ValidateToken(string token, List<Claim> listclaims, string clientIp, string serverIp)
    {
        // Busca o token no repositório
        RefreshToken refresh = _tokenService.GetByToken(token);

        // Se o token não existir, isso indica que é a primeira inserção
        if (refresh == null)
        {
            // Criando um novo token, já que este é o primeiro registro
            RevokeToken firstTokenCreation = new RevokeToken
            {
                Revoked = DateTime.UtcNow,  // Data de criação
                RevokedByIp = serverIp,
                IsRevoked = false,  // Não há motivo para revogação, pois é a primeira inserção
                NewToken = GenerateToken(listclaims),  // Gera um novo token
                ReasonRevoked = "Primeira criação do token"  // Motivo: primeira criação
            };

            // Retorna o novo token criado sem revogação
            return firstTokenCreation;
        }

        // Se o token já existir, realiza as verificações necessárias
        bool isExpired = refresh.RefreshTokenExpiryTime <= DateTime.UtcNow;
        bool ipMismatch = refresh.CreatedByIp != clientIp;  // Exemplo de verificação de IP diferente
        bool serverIpMismatch = refresh.RevokedByIp != serverIp;  // Verifica se o IP do servidor mudou
        bool shouldRevoke = isExpired || ipMismatch || serverIpMismatch;

        if (shouldRevoke)
        {
            // Token será revogado
            RevokeToken revokeToken = new RevokeToken
            {
                Revoked = DateTime.UtcNow,  // Data de revogação
                RevokedByIp = serverIp,
                IsRevoked = true,  // Token revogado
                NewToken = GenerateToken(listclaims),  // Gera um novo token
                ReasonRevoked = isExpired ? "Token expirado" :
                                ipMismatch ? "IP do cliente mudou" :
                                "IP do servidor mudou"
            };

            return revokeToken;
        }

        // Se não houver motivo para revogar, retorna que o token é válido
        return new RevokeToken
        {
            Revoked = DateTime.UtcNow,  // Data de verificação
            RevokedByIp = serverIp,
            IsRevoked = false,  // Não revogado
            NewToken = null,  // Nenhum novo token gerado
            ReasonRevoked = "Token válido"
        };
    }

    public TokenResult GetRefreshToken(string refreshToken)
    {
        // Valida o refresh token
        RefreshToken founded = _tokenService.GetRefreshToken(refreshToken);

        if (founded == null || founded.RefreshTokenExpiryTime > DateTime.Now)
        {
            throw new NullReferenceException("Refresh token inválido ou expirado.");
        }

        // Verifica se o usuário associado ao refresh token existe
        var usuario = _usuarioExternoService.GetById(founded.UsuarioId);
        if (usuario == null)
        {
            throw new Exception("Usuário associado ao refresh token não encontrado.");
        }

        // Gera um novo access token
        var authClaims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, usuario.Nome),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new Claim(ClaimTypes.Role, "admin")
            };

        var newAccessToken = GenerateToken(authClaims);

        var token = new TokenResult
        {
            AccessToken = newAccessToken,
            RefreshToken = refreshToken, // Retorna o mesmo refresh token
            AccessTokenExpiration = DateTime.UtcNow.AddMinutes(int.Parse(_configuration["JWTSettings:AccessTokenExpirationInMinutes"])),
            RefreshTokenExpiration = founded.Expires // Usar a data de expiração do refresh token existente
        };

        return token;
    }

    public List<RefreshToken> GetTokensByUserId(long id, TipoUsuario tipoUsuario)
    {
        throw new NotImplementedException();
    }

    object IAuthenticatorAppService.RefreshToken(string accessToken, string refreshToken, string? username)
    {
        throw new NotImplementedException();
    }

    public object RevokeToken(string username)
    {
        throw new NotImplementedException();
    }
}
