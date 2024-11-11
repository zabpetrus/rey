using AutoMapper;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Identity.Data;
using Microsoft.EntityFrameworkCore.ChangeTracking;
using Microsoft.EntityFrameworkCore.Metadata.Internal;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using Microsoft.Win32;
using Rey.Domain.Entities.Auth;
using Rey.Domain.Entities.Dto;
using Rey.Domain.Enums;
using Rey.Domain.Interfaces.IRepository;
using Rey.Domain.Interfaces.IServices;
using Rey.Domain.Services._Base;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Net;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Threading.Tasks;


namespace VEL.Domain.Service
{
    public class RefreshTokenService : ServiceBase<RefreshToken>, IRefreshTokenService
    {
        //Permissões
        private readonly IPermissaoRepository _permissaoExternaRepository;

        //Tabela Associativa  - Permissões
        private readonly IPermissaoUsuarioRepository _permissaoUsuarioRepository;

        //Tabela Associativa  - Perfis
        private readonly IPerfilUsuarioRepository _perfilUsuarioRepository;

        //Usuarios
        private readonly IUsuarioRepository _usuarioRepository;

        //Repositório do Refresh Token
        private readonly IRefreshTokenRepository _tokenRepository;

        //Serviços internos
        private readonly IHttpContextAccessor _httpContextAccessor;
        private readonly ILogger<RefreshTokenService> _logger;
        private readonly IConfiguration _configuration;
        private readonly IMapper _mapper;

       

        //Gera o Refresh Token 
        public string GenerateRefreshToken()
        {
            try
            {
                // Obtendo a chave secreta do JWT a partir das configurações
                string secretKey = _configuration["Auth:SecretKey"];
                if (string.IsNullOrWhiteSpace(secretKey))
                {
                    throw new InvalidOperationException("A chave secreta não pode estar vazia.");
                }

                // Gerando uma chave de comprimento fixo (256 bits) usando SHA256
                using (SHA256 sha256 = SHA256.Create())
                {
                    byte[] secretKeyBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(secretKey));

                    // Criando a chave de segurança simétrica
                    SymmetricSecurityKey signingKey = new SymmetricSecurityKey(secretKeyBytes);

                    // Criando as credenciais de assinatura
                    SigningCredentials creds = new SigningCredentials(signingKey, SecurityAlgorithms.HmacSha256);

                    // Criando o token JWT
                    JwtSecurityToken refreshToken = new JwtSecurityToken(
                        issuer: _configuration["JWTSettings:ValidIssuer"],
                        audience: _configuration["JWTSettings:ValidAudience"],
                        expires: DateTime.UtcNow.AddDays(30), // Validade maior para o refresh token
                        signingCredentials: creds
                    );

                    // Retornando o token como string
                    string tokenResult = new JwtSecurityTokenHandler().WriteToken(refreshToken);
                    if (string.IsNullOrEmpty(tokenResult))
                    {
                        throw new Exception("Erro durante a criação do Refresh Token.");
                    }

                    return tokenResult;
                }
            }
            catch (Exception ex)
            {
                throw new Exception($"Erro ao gerar o refresh token: {ex.Message}.");
            }
        }

        //Gera o Token baseado em Regras
        public string GenerateToken(List<Claim> userClaims)
        {
            try
            {
                // Verifica se userClaims é nulo
                if (userClaims == null || !userClaims.Any())
                {
                    throw new ArgumentException("As claims do usuário não podem estar vazias.");
                }

                // Obtendo a chave secreta do JWT a partir das configurações
                string secretKey = _configuration["Auth:SecretKey"];
                if (string.IsNullOrWhiteSpace(secretKey))
                {
                    throw new InvalidOperationException("A chave secreta não pode estar vazia.");
                }

                // Gerando uma chave de comprimento fixo (256 bits) usando SHA256
                using (SHA256 sha256 = SHA256.Create())
                {
                    byte[] secretKeyBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(secretKey));

                    // Criando a chave de segurança simétrica
                    SymmetricSecurityKey signingKey = new SymmetricSecurityKey(secretKeyBytes);

                    // Criando as credenciais de assinatura
                    SigningCredentials creds = new SigningCredentials(signingKey, SecurityAlgorithms.HmacSha256);

                    // Obtendo a validade do token a partir das configurações
                    if (!double.TryParse(_configuration["JWTSettings:AccessTokenExpirationInMinutes"], out double tokenValidityInMinutes) || tokenValidityInMinutes <= 0)
                    {
                        throw new InvalidOperationException("A validade do token é inválida.");
                    }

                    // Criando o token JWT
                    JwtSecurityToken jwtToken = new JwtSecurityToken(
                        issuer: _configuration["JWTSettings:ValidIssuer"],
                        audience: _configuration["JWTSettings:ValidAudience"],
                        expires: DateTime.UtcNow.AddMinutes(tokenValidityInMinutes),
                        claims: userClaims,
                        signingCredentials: creds
                    );

                    // Retornando o token como string
                    string tokenResult = new JwtSecurityTokenHandler().WriteToken(jwtToken);
                    if (string.IsNullOrEmpty(tokenResult))
                    {
                        throw new Exception("Erro durante a criação do Token.");
                    }

                    return tokenResult;
                }
            }
            catch (Exception ex)
            {
                throw new Exception($"Erro ao gerar o token: {ex.Message}.");
            }
        }

        //Renova o Token de Acesso
        public TokenResult RenovarToken(string refreshToken, List<Claim> claims)
        {
            // 1. Validação básica dos dados de entrada
            if (string.IsNullOrWhiteSpace(refreshToken) || claims == null || !claims.Any())
            {
                return new TokenResult() { Error = "Dados de entrada inválidos." };
            }

            try
            {
                // 2. Verificar se o Refresh Token existe no banco de dados
                var tokenNoBanco = _tokenRepository.GetByToken(refreshToken);

                // 3. Verificar se o Refresh Token é válido (não expirado, não revogado)
                if (tokenNoBanco == null || !tokenNoBanco.IsActive || tokenNoBanco.Expires <= DateTime.UtcNow)
                {
                    return new TokenResult() { Error = "Refresh token inválido, expirado ou revogado." };
                }

                // 4. Gerar um novo Access Token usando as claims do usuário
                var novoAccessToken = GenerateToken(claims);

                // 5. Verificar se o Refresh Token precisa ser renovado
                if (DeveRenovarRefreshToken(tokenNoBanco))
                {
                    AtualizarRefreshToken(tokenNoBanco); // Renova o Refresh Token se necessário
                }

                // 6. Configurar a expiração do Access Token (obtida das configurações)
                if (!int.TryParse(_configuration["JWTSettings:AccessTokenExpirationInMinutes"], out int accessTokenExpirationInMinutes) || accessTokenExpirationInMinutes <= 0)
                {
                    throw new InvalidOperationException("Configuração de expiração do Access Token inválida.");
                }

                // 7. Retornar o novo Access Token e o Refresh Token (renovado ou não)
                return new TokenResult
                {
                    AccessToken = novoAccessToken,
                    RefreshToken = tokenNoBanco.Token, // Mesmo Refresh Token ou renovado, dependendo da condição
                    AccessTokenExpiration = DateTime.UtcNow.AddMinutes(accessTokenExpirationInMinutes),
                    RefreshTokenExpiration = tokenNoBanco.Expires // Mantém a expiração original ou a renovada
                };
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Erro durante a renovação do token.");
                return new TokenResult() { Error = "Erro ao renovar o token." };
            }
        }

        //Reseta senha
        public bool ResetPassword(string token, string novasenha)
        {
            // Validar o token de reset de senha e procurar o usuário correspondente

            _logger.LogInformation("Iniciando processo de redefinição de senha.");


            Usuario usuario = _usuarioRepository.GetByResetPasswordToken(token);

            if (usuario == null || string.IsNullOrEmpty(novasenha))
            {
                _logger.LogWarning("Token inválido ou expirado para redefinição de senha.");
                return false;
            }

            // Redefinir a senha (criptografar a nova senha antes de armazenar)
            usuario.RedefinirSenha(novasenha);
            _usuarioRepository.Update(usuario);
            return true;

        }

        //Registro de Usuario  
        public TokenResult Registro(Register registration)
        {
            var novoUsuario = ValidateRegistrationUsuario(registration);

            if (novoUsuario == null)
            {
                throw new Exception("Houve um erro ao recupear os dados: Usuario nulo");
            }

            // Salva o novo usuário no banco de dados e retorna a instância criada
            Usuario usuario = _usuarioRepository.CreateAndGet(novoUsuario);

            if (usuario == null)
            {
                throw new Exception("Houve um erro ao gerar o registro");
            }

            TokenResult response = SetInternalCredentials(usuario);
            return response;
        }


        //Revogar todos os tokens pelo username e o tipo de usuario
        public bool RevogarTodosTokens(string username, TipoUsuario tipoUsuario)
        {
            // Declarando uma variável para armazenar o usuário
            object usuario = null;

            // Buscar o usuário no banco de dados de acordo com o tipo de usuário
            if (tipoUsuario == TipoUsuario.)
            {
                usuario = _usuarioRepository.FindUser(username);
            }
            else if (tipoUsuario == TipoUsuario.)
            {
                usuario = _usuarioRepository.FindUser(username);
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
            else if (usuario is Usuario interno)
            {
                usuarioId = interno.Id; // Atribuindo o ID do usuário interno
            }
            else
            {
                return false; // Tipo de usuário inválido
            }

            // Buscar todos os tokens de refresh associados ao usuário
            List<RefreshToken> tokens = _tokenRepository.GetRefreshTokenByUsuarioId(usuarioId);
            if (tokens == null || !tokens.Any())
            {
                return false; // Não há tokens para este usuário
            }

            // Remover todos os tokens do banco de dados
            foreach (var token in tokens)
            {
                _tokenRepository.DeleteById(token.Id);
            }

            return true; // Tokens revogados com sucesso
        }


        //Revogar um token dado um determinado token
        public bool RevokeTokens(string token)
        {
            try
            {
                // Verifica se o Refresh Token existe no banco de dados
                RefreshToken refreshToken = _tokenRepository.GetRefreshToken(token);

                if (refreshToken == null)
                {
                    _logger.LogWarning($"Tentativa de revogar um token inexistente: {token}");
                    return false; // Token não encontrado
                }

                // Revogar o token removendo-o do banco de dados
                bool revoked = _tokenRepository.RemoveRefreshToken(refreshToken);

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


        //Obtendo o ClaimPrincipal a partir de um accestoken
        public ClaimsPrincipal GetPrincipalFromToken(string accessToken)
        {
            // Retorna erro se o token for nulo ou vazio
            if (string.IsNullOrEmpty(accessToken))
            {
                return new ValidatorResponse
                {
                    Status = false,
                    ErrorMessage = "Não foi fornecido um token de acesso válido."
                };
            }

            try
            {
                // Obtendo a chave secreta do JWT a partir das configurações
                string secretKey = _configuration["Auth:SecretKey"];

                if (string.IsNullOrWhiteSpace(secretKey))
                {
                    throw new InvalidOperationException("A chave secreta não pode estar vazia.");
                }

                // Convertendo a chave secreta para um array de bytes
                byte[] secretKeyBytes = Encoding.UTF8.GetBytes(secretKey);

                // Verificando se a conversão resultou em um array nulo
                if (secretKeyBytes == null || secretKeyBytes.Length == 0)
                {
                    throw new InvalidOperationException("Erro durante a codificação.");
                }

                // Criando a chave de segurança simétrica
                SymmetricSecurityKey signingKey = new SymmetricSecurityKey(secretKeyBytes);

                var tokenHandler = new JwtSecurityTokenHandler();

                // Configurando os parâmetros de validação do token
                var validationParameters = new TokenValidationParameters
                {
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = signingKey,
                    ValidateIssuer = true,
                    ValidIssuer = _configuration["JWTSettings:ValidIssuer"],
                    ValidateAudience = true,
                    ValidAudience = _configuration["JWTSettings:ValidAudience"],
                    ClockSkew = TimeSpan.Zero // Remove a tolerância de tempo
                };

                // Valida o token e retorna os claims
                ClaimsPrincipal response = tokenHandler.ValidateToken(accessToken, validationParameters, out SecurityToken validatedToken);

                if (response == null)
                {
                    throw new Exception("Erro durante a extração das claims");
                }

                // Se a validação for bem-sucedida, retorna sucesso
                return new ValidatorResponse
                {
                    Status = true,
                    ClaimsPrincipal = response
                };
            }
            catch (SecurityTokenExpiredException)
            {
                throw new SecurityTokenExpiredException("SecurityTokenExpiredException: Token expirado.");
            }
            catch (SecurityTokenException)
            {
                throw new SecurityTokenException("SecurityTokenException: Token inválido.");
            }
            catch (Exception ex)
            {
                // Outros erros de validação
                _logger.LogError("Erro ao validar o token: {Message}", ex.Message);

                return new ValidatorResponse
                {
                    Status = false,
                    ErrorMessage = ex.Message
                };
            }
        }


        //Login 
        public TokenResult Login(string username, string password)
        {
            try
            {
                Usuario usuarioexterno = _usuarioRepository.FindUser(username);

                // Verifica se o usuário foi encontrado
                if (usuarioexterno == null)
                {
                    throw new Exception($"Erro na recuperação de usuário: Usuário não encontrado para o username: {username}");

                }

                // Verifica se a senha está correta
                if (!usuarioexterno.VerificarSenha(password))
                {
                    throw new Exception("Erro na validação de usuário");
                }

                TokenResult response = SetExternalCredentials(usuarioexterno);

                if (response == null || string.IsNullOrEmpty(response.AccessToken))
                {
                    throw new Exception("Erro na criação do token: " + response.Error);
                }

                return response;
            }
            catch (Exception ex)
            {
                _logger.LogError("Erro ao realizar login externo: " + ex.Message);
                return new TokenResult { Error = "Erro: " + ex.Message };
            }
        }


        //Obter o RefreshToken, AccessToken e suas expirações dado um refreshToken
        public TokenResult GetRefreshToken(string refreshToken)
        {
            // Valida o refresh token
            RefreshToken founded = _tokenRepository.GetRefreshToken(refreshToken);

            if (founded == null || founded.RefreshTokenExpiryTime < DateTime.Now)
            {
                throw new ArgumentException("Refresh token inválido ou expirado.");
            }

            // Enum: pode ser interno ou externo
            TipoUsuario tipoUsuario = founded.TipoUsuario;

            if (tipoUsuario == null)
            {
                throw new InvalidOperationException("Não foi possível determinar o tipo de usuário.");
            }

            // Verifica se o usuário associado ao refresh token existe
            Usuario usuario = null;
            Usuario usuario = null;

            if (tipoUsuario == TipoUsuario.)
            {
                usuario = _usuarioRepository.GetById(founded.UsuarioId)
                    ?? throw new KeyNotFoundException("Usuário associado ao refresh token não encontrado.");
            }
            else if (tipoUsuario == TipoUsuario.)
            {
                usuario = _usuarioRepository.GetById(founded.UsuarioId)
                    ?? throw new KeyNotFoundException("Usuário associado ao refresh token não encontrado.");
            }

            // Determina o usuário (interno ou externo)
            if (usuario == null && usuario == null)
            {
                throw new InvalidOperationException("Usuário não encontrado.");
            }

            // Gera um novo access token
            var authClaims = new List<Claim>();

            if (usuario != null)
            {
                authClaims.Add(new Claim(JwtRegisteredClaimNames.Sub, usuario.Nome)); // Subject (nome do usuário)
                authClaims.Add(new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())); // ID do token (único)
                authClaims.Add(new Claim(JwtRegisteredClaimNames.NameId, usuario.Id.ToString())); // ID do usuário
                authClaims.Add(new Claim("UserId", usuario.Id.ToString())); // ID do usuário (claim personalizada)
                authClaims.Add(new Claim(ClaimTypes.Name, usuario.Nome)); // Nome do usuário
                authClaims.Add(new Claim(ClaimTypes.Role, "admin")); // Papel do usuário (admin)
                authClaims.Add(new Claim("Uso", "")); // Informações extras de uso
            }
            else if (usuario != null)
            {
                authClaims.Add(new Claim(JwtRegisteredClaimNames.Sub, usuario.Nome)); // Subject (nome do usuário)
                authClaims.Add(new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())); // ID do token (único)
                authClaims.Add(new Claim(JwtRegisteredClaimNames.NameId, usuario.Id.ToString())); // ID do usuário
                authClaims.Add(new Claim("UserId", usuario.Id.ToString())); // ID do usuário (claim personalizada)
                authClaims.Add(new Claim(ClaimTypes.Name, usuario.Nome)); // Nome do usuário
                authClaims.Add(new Claim(ClaimTypes.Role, "admin")); // Papel do usuário (admin)
                authClaims.Add(new Claim("Uso", "")); // Informações extras de uso
            }

            var newAccessToken = GenerateToken(authClaims);

            var token = new TokenResult
            {
                AccessToken = newAccessToken,
                RefreshToken = refreshToken, // Retorna o mesmo refresh token
                AccessTokenExpiration = DateTime.UtcNow.AddMinutes(int.Parse(_configuration["JWTSettings:AccessTokenExpirationInMinutes"])),
                RefreshTokenExpiration = founded.Expires // Usa a data de expiração do refresh token existente
            };

            return token;
        }


        //Retorna o acess token
        public string RevokeTokensForClaims(ClaimsPrincipal tokenClaims)
        {
            try
            {
                // Verifica se o ClaimsPrincipal é válido e se o usuário está autenticado
                if (tokenClaims == null || !tokenClaims.Identity.IsAuthenticated)
                {
                    throw new UnauthorizedAccessException("Token claims não são válidos ou o usuário não está autenticado.");
                }

                // Busca a lista de RefreshTokens com base no papel e ID do usuário
                List<RefreshToken> refreshTokens = FindRefreshTokenByRoleAndId(tokenClaims);

                if (refreshTokens == null || refreshTokens.Count == 0)
                {
                    throw new InvalidOperationException("Erro no fornecimento das regras de usuário: ");
                }

                bool allTokensRevoked = true;

                // Revoga cada RefreshToken encontrado
                foreach (var token in refreshTokens)
                {
                    // Chamando um método que revoga o RefreshToken
                    RevokeToken temp = _tokenRepository.RevokeRefreshToken(token);

                    // Verifica se ocorreu um erro na revogação do token
                    if (temp == null || !string.IsNullOrEmpty(temp.Error))
                    {
                        allTokensRevoked = false; // Pelo menos um token não foi revogado
                        _logger.LogError("Erro ao revogar o RefreshToken com ID: {TokenId}, Erro: {Error}", token.Id, temp?.Error);
                        continue; // Continua com o próximo token
                    }

                    if (!temp.IsRevoked)
                    {
                        allTokensRevoked = false; // O token não foi revogado
                        _logger.LogError("Falha ao revogar o RefreshToken com ID: {TokenId}", token.Id);
                    }
                }

                // Retorna verdadeiro se todos os tokens foram revogados com sucesso
                return new LogoutResponse()
                {
                    Success = allTokensRevoked
                };
            }
            catch (Exception ex)
            {
                // Loga a exceção para rastreamento, se necessário
                _logger.LogError(ex, "Erro ao revogar tokens: {Message}", ex.Message);

                return new LogoutResponse()
                {
                    Success = false,
                    ErrorMessage = ex.Message
                };
            }
        }
  
        //Reset de Senha de Usuários s
        public string GeneratePasswordResetTokenExternal(string email)
        {
            // Define o token de acesso
            RefreshToken token = _tokenRepository.FindTokenByEmail(email);

            if (token == null)
            {
                throw new AppExceptions("Usuario não encontrado", 404);
            }

            List<Claim> claimsList = GetClaimsByUserExternal(token.UsuarioId);
            // Gera o token de redefinição de senha a partir da lista de claims
            return GenerateToken(claimsList);
        }


        //Lista de Claims de um usuario externo dado um id de Usuario 
        private List<Claim> GetClaimsByUserExternal(long usuarioId)
        {
            Usuario user = _usuarioRepository.GetById(usuarioId);

            List<PermissaoExterna> listapermissoesexternas = _permissaoUsuarioRepository.FindPermissionsByUserId(usuarioId);
            if (listapermissoesexternas == null)
            {
                throw new Exception("Erro durante a operação...");
            }

            List<Perfil> listaPerfiss = _perfilUsuarioRepository.FindProfileByUserId(usuarioId);
            if (listaPerfiss == null)
            {
                throw new Exception("Erro durante a obteñção dos perfis ...");
            }

            List<Claim> authClaims = new List<Claim>();

            // Adicionando claims
            authClaims.Add(new Claim(JwtRegisteredClaimNames.Sub, user.Nome)); // Nome do usuário
            authClaims.Add(new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())); // ID do token
            authClaims.Add(new Claim(JwtRegisteredClaimNames.NameId, user.Id.ToString())); // ID do usuário
            authClaims.Add(new Claim("UserId", user.Id.ToString())); // Claim personalizada para o ID do usuário
            authClaims.Add(new Claim(ClaimTypes.Name, user.Nome)); // Nome do usuário
            authClaims.Add(new Claim("Uso", "")); // Informações adicionais sobre o uso

            foreach (var permissao in listapermissoesexternas)
            {
                authClaims.Add(new Claim(ClaimTypes.Role, permissao.Nome)); // Adiciona a permissão como claim de papel
            }

            foreach (var perfis in listaPerfiss)
            {
                authClaims.Add(new Claim(ClaimTypes.Role, perfis.TipoDeUsuario.ToString())); // Adiciona a permissão como claim de papel
            }

            // Retornar os claims de autenticação
            return authClaims;
        }

        /*
         * **** Métodos Privados **** *
         */

        //Metodo dedicado para criação de Credenciais para Usuarios s. O padrão é guest
        private TokenResult SetInternalCredentials(Usuario usuario)
        {
            try
            {
                // Define o uso com base no tipo do usuário
                string uso = "";

                // Criação dos claims de autenticação
                List<Claim> authClaims = GetClaimsByUserInternal(usuario.Id);

                // Geração dos tokens
                string accessToken = GenerateToken(authClaims);
                string refreshToken = GenerateRefreshToken();

                // Obter IP do cliente e do servidor
                string createdByIp = GetClientIpAddress();
                string serverIp = GetServerIpAddress();

                // Obtenção da validade do refresh token
                if (!int.TryParse(_configuration["JWTSettings:RefreshTokenExpirationInDays"], out int refreshTokenValidityInDays))
                {
                    throw new InvalidOperationException("Erro ao obter validade do RefreshToken.");
                }

                // Validação do token e IPs gerados
                if (string.IsNullOrEmpty(accessToken) || string.IsNullOrEmpty(refreshToken))
                {
                    throw new InvalidOperationException("Falha na geração do token.");
                }

                // Validação do token
                RevokeToken revokeToken = ValidateToken(accessToken, authClaims, createdByIp, serverIp);

                // Criação do refresh token
                RefreshToken refresh = new RefreshToken
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
                    TipoUsuario = TipoUsuario., // Manter o tipo correto do usuário
                    RefreshTokenReset = GenerateRefreshToken(),
                    RefreshTokenExpiryTime = DateTime.UtcNow.AddDays(refreshTokenValidityInDays),
                    ResetPasswordTokenExpiration = DateTime.UtcNow.AddDays(2)
                };

                // Persistir o refresh token no repositório
                RefreshToken response = _tokenRepository.CreateAndGet(refresh)
                                     ?? throw new InvalidOperationException("Falha ao gravar o token no banco de dados.");

                if (!int.TryParse(_configuration["JWTSettings:AccessTokenExpirationInMinutes"], out int accessTokenValidityInMinutes))
                {
                    throw new InvalidOperationException("Erro ao obter validade do AccessToken.");
                }

                // Montando a resposta do token
                TokenResult tokenViewModel = new TokenResult
                {
                    AccessToken = accessToken,
                    RefreshToken = refreshToken,
                    AccessTokenExpiration = DateTime.UtcNow.AddMinutes(accessTokenValidityInMinutes),
                    RefreshTokenExpiration = DateTime.UtcNow.AddDays(refreshTokenValidityInDays)
                };

                return tokenViewModel;
            }
            catch (Exception ex)
            {
                // Logar a exceção aqui, se necessário
                return new TokenResult
                {
                    Error = ex.Message,
                };
            }
        }


        //Metodo dedicado para criação de Credenciais para Usuarios s. O padrão é guest
        private TokenResult SetExternalCredentials(Usuario usuario)
        {
            try
            {
                // Define o uso com base no tipo do usuário
                string uso = "";

                // Criação dos claims de autenticação
                List<Claim> authClaims = GetClaimsByUserExternal(usuario.Id);

                // Geração dos tokens
                string accessToken = GenerateToken(authClaims);
                string refreshToken = GenerateRefreshToken();

                // Obter IP do cliente e do servidor
                string createdByIp = GetClientIpAddress();
                string serverIp = GetServerIpAddress();

                // Obtenção da validade do refresh token
                if (!int.TryParse(_configuration["JWTSettings:RefreshTokenExpirationInDays"], out int refreshTokenValidityInDays))
                {
                    throw new InvalidOperationException("Erro ao obter validade do RefreshToken.");
                }

                // Validação do token e IPs gerados
                if (string.IsNullOrEmpty(accessToken) || string.IsNullOrEmpty(refreshToken))
                {
                    throw new InvalidOperationException("Falha na geração do token.");
                }

                // Validação do token
                RevokeToken revokeToken = ValidateToken(accessToken, authClaims, createdByIp, serverIp);

                // Criação do refresh token
                RefreshToken refresh = new RefreshToken
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
                    TipoUsuario = TipoUsuario., // Manter o tipo correto do usuário
                    RefreshTokenReset = GenerateRefreshToken(),
                    RefreshTokenExpiryTime = DateTime.UtcNow.AddDays(refreshTokenValidityInDays),
                    ResetPasswordTokenExpiration = DateTime.UtcNow.AddDays(2)
                };

                // Persistir o refresh token no repositório
                RefreshToken response = _tokenRepository.CreateAndGet(refresh)
                                     ?? throw new InvalidOperationException("Falha ao gravar o token no banco de dados.");

                if (!int.TryParse(_configuration["JWTSettings:AccessTokenExpirationInMinutes"], out int accessTokenValidityInMinutes))
                {
                    throw new InvalidOperationException("Erro ao obter validade do AccessToken.");
                }

                // Montando a resposta do token
                TokenResult tokenViewModel = new TokenResult
                {
                    AccessToken = accessToken,
                    RefreshToken = refreshToken,
                    AccessTokenExpiration = DateTime.UtcNow.AddMinutes(accessTokenValidityInMinutes),
                    RefreshTokenExpiration = DateTime.UtcNow.AddDays(refreshTokenValidityInDays)
                };

                return tokenViewModel;
            }
            catch (Exception ex)
            {
                // Logar a exceção aqui, se necessário
                return new TokenResult
                {
                    Error = ex.Message,
                };
            }
        }


        //Gera um novo TokenResult a partir do DTo de entrada 
        private List<RefreshToken> FindRefreshTokenByRoleAndId(ClaimsPrincipal tokenClaims)
        {
            try
            {
                // Verifica se o ClaimsPrincipal é nulo
                if (tokenClaims == null)
                {
                    throw new ArgumentNullException(nameof(tokenClaims), "Objeto nulo");
                }

                // Busca o ID do usuário e a claim de uso
                Claim? userIdClaim = tokenClaims.FindFirst("UserId");
                Claim? usernameClaim = tokenClaims.FindFirst(ClaimTypes.NameIdentifier);
                Claim? usoClaim = tokenClaims.FindFirst("Uso");

                // Verifica se as claims são válidas
                if (userIdClaim == null || usoClaim == null)
                {
                    throw new InvalidOperationException("As claims necessárias não estão presentes.");
                }

                string userIdString = userIdClaim.Value;

                string uso = usoClaim.Value;

                // Verifica se o userIdString é um número válido
                if (!long.TryParse(userIdString, out long userId))
                {
                    throw new FormatException($"O ID do usuário '{userIdString}' não está no formato correto.");
                }

                // Com base na claim de uso, busca o usuário e seus tokens
                if (uso == "")
                {
                    Usuario usuario = _usuarioRepository.GetById(userId);
                    if (usuario == null)
                    {
                        throw new InvalidOperationException("Usuário interno não encontrado.");
                    }
                    return _tokenRepository.FindTokensByUserInternal(usuario);
                }
                else if (uso == "")
                {
                    Usuario usuario = _usuarioRepository.GetById(userId);
                    if (usuario == null)
                    {
                        throw new InvalidOperationException("Usuário externo não encontrado.");
                    }
                    var tokens = _tokenRepository.FindTokensByUserExternal(usuario);

                    return tokens;

                }
                else
                {
                    throw new InvalidOperationException("Tipo de uso desconhecido. Deve ser '' ou ''.");
                }
            }
            catch (Exception)
            {
                throw;
            }
        }


        //Verfifca se vai expirar um dia antes do prazo
        private bool DeveRenovarRefreshToken(RefreshToken token)
        {
            return token.Expires < DateTime.UtcNow.AddDays(1);
        }


        //Atualiza o RefreshToken
        private void AtualizarRefreshToken(RefreshToken token)
        {

            // Gera um novo Refresh Token e atualiza suas propriedades
            string novoRefreshToken = GenerateRefreshToken();

            token.Token = novoRefreshToken;
            token.Expires = DateTime.UtcNow.AddDays(7);
            token.Created = DateTime.UtcNow;

            // Atualiza o token no banco de dados
            _tokenRepository.Update(token);
        }


        //Criar um RevokeToken a partir de um token, lista de permissoes, ip do cliente e o ip do servidor
        private RevokeToken ValidateToken(string token, List<Claim> listClaims, string clientIp, string serverIp)
        {
            try
            {
                // Busca o token no repositório
                RefreshToken refresh = _tokenRepository.GetByToken(token);

                // Se o token não existir, isso indica que é a primeira inserção
                if (refresh == null)
                {
                    // Criando um novo token, já que este é o primeiro registro
                    return new RevokeToken
                    {
                        Revoked = DateTime.UtcNow,  // Data de criação
                        RevokedByIp = serverIp,
                        IsRevoked = false,  // Não há motivo para revogação, pois é a primeira inserção
                        NewToken = GenerateToken(listClaims),  // Gera um novo token
                        ReasonRevoked = "Primeira criação do token"  // Motivo: primeira criação
                    };
                }

                // Se o token já existir, realiza as verificações necessárias
                bool isExpired = refresh.RefreshTokenExpiryTime <= DateTime.UtcNow;
                bool ipMismatch = refresh.CreatedByIp != clientIp;  // Verificação de IP diferente
                bool serverIpMismatch = refresh.RevokedByIp != serverIp;  // Verifica se o IP do servidor mudou
                bool shouldRevoke = isExpired || ipMismatch || serverIpMismatch;

                if (shouldRevoke)
                {
                    // Token será revogado
                    return new RevokeToken
                    {
                        Revoked = DateTime.UtcNow,  // Data de revogação
                        RevokedByIp = serverIp,
                        IsRevoked = true,  // Token revogado
                        NewToken = GenerateToken(listClaims),  // Gera um novo token
                        ReasonRevoked = isExpired ? "Token expirado" :
                                        ipMismatch ? "IP do cliente mudou" :
                                        "IP do servidor mudou"
                    };
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
            catch (Exception ex)
            {
                // Captura qualquer exceção e retorna uma mensagem de erro
                return new RevokeToken { Error = ex.Message };
            }
        }


        // Método para obter o IP do cliente
        private string GetClientIpAddress()
        {
            return _httpContextAccessor.HttpContext?.Connection?.RemoteIpAddress?.ToString()
                   ?? throw new InvalidOperationException("IP do cliente não pode ser obtido.");
        }


        // Método para obter o IP do servidor
        private string GetServerIpAddress()
        {
            return Dns.GetHostAddresses(Dns.GetHostName()).FirstOrDefault()?.ToString()
                   ?? throw new InvalidOperationException("IP do servidor não pode ser obtido.");
        }

         //Método para validar a criação de um usuário 
        private Usuario ValidateRegistrationUsuario(Register registration)
        {
            // Verifica se o registro contém os dados necessários
            if (string.IsNullOrWhiteSpace(registration.Cpf) &&
                string.IsNullOrWhiteSpace(registration.Email) &&
                string.IsNullOrWhiteSpace(registration.Nome))
            {
                throw new ArgumentException("É necessário fornecer pelo menos um dos seguintes dados: CPF, Email ou Nome.");
            }

            // Verifica se já existe um usuário com o mesmo CPF ou Email
            if (!string.IsNullOrWhiteSpace(registration.Cpf))
            {
                Usuario usuarioExistentePorCpf = _usuarioRepository.FindUserByCpf(registration.Cpf);

                if (usuarioExistentePorCpf != null)
                {
                    throw new InvalidOperationException("Este usuário já está registrado.");
                }
            }

            if (!string.IsNullOrWhiteSpace(registration.Email))
            {
                Usuario usuarioExistentePorEmail = _usuarioRepository.FindUserByEmail(registration.Email);

                if (usuarioExistentePorEmail != null)
                {
                    throw new InvalidOperationException("Este usuário já está registrado.");
                }
            }

            // Cria uma nova instância de Usuario a partir do DTO Registration
            Usuario novoUsuario = new Usuario
            {
                Nome = registration.Nome,
                Cpf = registration.Cpf,
                Email = registration.Email,
                Telefone = registration.Telefone,
                Ativo = registration.Ativo
            };

            // Configura a senha do novo usuário
            novoUsuario.ConfigurarSenha(registration.Senha);

            return novoUsuario;
        }


        //Validando o ip do cliente e do servidor
        public bool ValidateClientAndServerIp(string clientIp, string serverIp)
        {
            // Verificar se os IPs são válidos
            if (!IPAddress.TryParse(clientIp, out IPAddress clientAddress) || !IPAddress.TryParse(serverIp, out IPAddress serverAddress))
            {
                throw new ArgumentException("Os IPs fornecidos não são válidos.");
            }

            // Verificar se os IPs são endereços de loopback ou reservados
            if (IPAddress.IsLoopback(clientAddress) || IPAddress.IsLoopback(serverAddress) ||
                IsReserved(clientAddress) || IsReserved(serverAddress))
            {
                throw new ArgumentException("Os IPs fornecidos não são permitidos.");
            }

            // Verificar se os IPs são exatamente iguais
            if (clientAddress.Equals(serverAddress))
            {
                return true; // Os IPs são idênticos
            }

            // Verificar se os IPs estão na mesma família de endereços (IPv4 ou IPv6)
            if (clientAddress.AddressFamily != serverAddress.AddressFamily)
            {
                return false; // IPs não pertencem à mesma família
            }

            // Verificar se os IPs estão na mesma sub-rede
            if (IsSameSubnet(clientAddress, serverAddress))
            {
                return true; // Os IPs estão na mesma sub-rede
            }

            return false; // IPs são diferentes e não pertencem à mesma sub-rede
        }


        // Método auxiliar para verificar se dois IPs estão na mesma sub-rede
        private bool IsSameSubnet(IPAddress ip1, IPAddress ip2, int prefixLength = 24)
        {
            byte[] addressBytes1 = ip1.GetAddressBytes();
            byte[] addressBytes2 = ip2.GetAddressBytes();

            if (addressBytes1.Length != addressBytes2.Length)
            {
                return false; // Comprimentos diferentes, não podem estar na mesma sub-rede
            }

            // Converter o comprimento do prefixo em uma máscara de sub-rede
            int fullBytes = prefixLength / 8;
            int remainingBits = prefixLength % 8;

            // Comparar os bytes completos
            for (int i = 0; i < fullBytes; i++)
            {
                if (addressBytes1[i] != addressBytes2[i])
                {
                    return false;
                }
            }

            // Comparar os bits restantes, se houver
            if (remainingBits > 0)
            {
                int mask = 0xFF << (8 - remainingBits);
                if ((addressBytes1[fullBytes] & mask) != (addressBytes2[fullBytes] & mask))
                {
                    return false;
                }
            }

            return true; // IPs estão na mesma sub-rede
        }


        // Método auxiliar para verificar endereços reservados
        private bool IsReserved(IPAddress address)
        {
            byte[] bytes = address.GetAddressBytes();

            if (address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork) // IPv4
            {
                // Verifica os endereços IPv4 reservados
                // 10.0.0.0 a 10.255.255.255
                if (bytes[0] == 10)
                {
                    return true;
                }

                // 172.16.0.0 a 172.31.255.255
                if (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31)
                {
                    return true;
                }

                // 192.168.0.0 a 192.168.255.255
                if (bytes[0] == 192 && bytes[1] == 168)
                {
                    return true;
                }

                // 169.254.0.0 a 169.254.255.255 (Link-local)
                if (bytes[0] == 169 && bytes[1] == 254)
                {
                    return true;
                }
            }
            else if (address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6) // IPv6
            {
                // Verifica os endereços IPv6 reservados
                // fe80::/10 (Link-local)
                if (bytes[0] == 0xfe && (bytes[1] & 0xc0) == 0x80)
                {
                    return true;
                }
            }

            return false;
        }


        //Extraindo o id dos claims, Já que um usuario pode ter credenciais internas e externas
        private long GetExternalUserByAccessToken(string accessToken)
        {
            // Validação e obtenção das claims do token
            ValidatorResponse validatorResponse = GetPrincipalFromToken(accessToken);

            if (!validatorResponse.Status || validatorResponse.ClaimsPrincipal == null)
            {
                throw new InvalidOperationException("Falha na validação do token:" + validatorResponse.ErrorMessage);
            }

            // Extrair o ID do usuário das claims
            string? userId = validatorResponse.ClaimsPrincipal.Claims.FirstOrDefault(c => c.Type == "userId")?.Value;

            if (string.IsNullOrEmpty(userId) || !long.TryParse(userId, out long parsedUserId))
            {
                throw new InvalidOperationException("ID do usuário não encontrado ou inválido nas claims.");
            }

            return parsedUserId;
        }


        //Encontrando o usuario pelo AccessToKen
        public Usuario? FindExternalUserByAccessToken(string accessToken)
        {
            //Obtendo o userid
            long parsedUserId = GetExternalUserByAccessToken(accessToken);

            // Consultar o repositório para obter o RefreshToken associado ao usuário
            List<RefreshToken> refreshTokens = _usuarioRepository.GetRefreshTokenByUsuarioId(parsedUserId);

            if (!refreshTokens.Any())
            {
                throw new InvalidOperationException("Nenhum RefreshToken encontrado para o ID do usuário fornecido.");
            }

            // Obter o usuário externo associado ao RefreshToken
            Usuario? usuario = _usuarioRepository.GetById(parsedUserId);

            if (usuario == null)
            {
                throw new InvalidOperationException("Usuário externo não encontrado.");
            }

            return usuario;
        }


        //Validando O token 
        public bool ValidateExternalToken(string accesstoken)
        {
            long parsedUserId = GetExternalUserByAccessToken(accesstoken);

            // 3. Consultar o repositório para obter os RefreshTokens associados ao usuário
            List<RefreshToken> refreshTokens = _tokenRepository.GetRefreshTokenByUsuarioId(parsedUserId);

            if (refreshTokens == null || !refreshTokens.Any())
            {
                _logger.LogWarning("Nenhum RefreshToken encontrado para o ID do usuário {UserId}.", parsedUserId);
                return false;  // Se não houver tokens, o acesso é inválido
            }

            // 4. Verificar se algum dos tokens é válido
            foreach (var refreshToken in refreshTokens)
            {
                // Se o token foi revogado, retornamos falso
                if (refreshToken.IsRevoked)
                {
                    _logger.LogWarning("O RefreshToken associado ao usuário {UserId} foi revogado.", parsedUserId);
                    return false;
                }

                // Se o token expirou, retornamos falso
                if (refreshToken.IsExpired)
                {
                    _logger.LogWarning("O RefreshToken associado ao usuário {UserId} expirou.", parsedUserId);
                    return false;
                }

                // Se o token foi substituído por outro token, retornamos falso
                if (!string.IsNullOrEmpty(refreshToken.ReplacedByToken))
                {
                    _logger.LogWarning("O RefreshToken associado ao usuário {UserId} foi substituído.", parsedUserId);
                    return false;
                }

                // Se encontramos um token válido, podemos retornar true
                if (refreshToken.IsActive)
                {
                    return true;  // Token válido, não revogado e não expirado
                }
            }

            // Se nenhum token válido foi encontrado
            _logger.LogWarning("Nenhum token válido encontrado para o usuário {UserId}.", parsedUserId);
            return false;
        }

    }
}
