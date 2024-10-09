using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Rey.Application.Interfaces;
using Rey.Application.ViewModel;

namespace Rey.Api.Controllers
{
    /// <summary>
    /// Usuario Externo Controller
    /// </summary>
    [Route("api/[controller]")]
    [ApiController]
    public class UsuarioExternoController : ControllerBase
    {
        private readonly IUsuarioExternoAppService _usuarioExternoAppService;
        private readonly ILogger _logger;

        public UsuarioExternoController(IUsuarioExternoAppService usuarioExternoAppService, ILogger logger)
        {
            _usuarioExternoAppService = usuarioExternoAppService;
            _logger = logger;
        }

        /// <summary>
        /// Get All
        /// </summary>
        /// <returns>An IActionResult.</returns>
        [HttpGet]
        public IActionResult GetAll()
        {
            try
            {
                _logger.LogInformation("Tentando obter todos os usuários.");
                List<UsuarioExternoViewModel> lista = _usuarioExternoAppService.GetAll();
                if (lista == null)
                {
                    _logger.LogWarning("Nenhum usuário encontrado.");
                    return NotFound("Nenhum usuário encontrado.");
                }
                return Ok(lista);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Erro ao tentar obter todos os usuários.");
                return StatusCode(StatusCodes.Status500InternalServerError, "Erro interno no servidor.");
            }
        }

        /// <summary>
        /// Get By Id
        /// </summary>
        /// <param name="id">An Id</param>
        /// <returns>An IActionResult.</returns>
        [HttpGet("{id:long}")]
        public IActionResult GetById(long id)
        {
            try
            {
                if (id <= 0)
                {
                    _logger.LogWarning("ID inválido fornecido: {id}", id);
                    return BadRequest("ID inválido.");
                }

                _logger.LogInformation("Tentando obter usuário com ID: {id}", id);
                List<UsuarioExternoViewModel> usuarios = _usuarioExternoAppService.GetById(id);

                if (usuarios == null)
                {
                    _logger.LogWarning("Usuário com ID {id} não encontrado.", id);
                    return NotFound($"Usuário com ID {id} não encontrado.");
                }

                return Ok(usuarios);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Erro ao tentar obter usuário por ID {id}.", id);
                return StatusCode(StatusCodes.Status500InternalServerError, "Erro interno no servidor.");
            }
        }

        /// <summary>
        /// Create User
        /// </summary>
        /// <param name="usuarioExternoViewModel">A Usuario Externo View Model</param>
        /// <returns>An IActionResult.</returns>
        [HttpPost]
        public IActionResult Create([FromBody] UsuarioExternoViewModel usuarioExternoViewModel)
        {
            try
            {
                if (usuarioExternoViewModel == null)
                {
                    _logger.LogWarning("Tentativa de criar usuário com dados inválidos.");
                    return BadRequest("Dados inválidos.");
                }

                _logger.LogInformation("Tentando criar um novo usuário.");
                UsuarioExternoViewModel usuario = _usuarioExternoAppService.CreateAndGet(usuarioExternoViewModel);
                return StatusCode(StatusCodes.Status201Created, usuario); // Retorna 201 Created com o objeto criado

            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Erro ao tentar criar um novo usuário.");
                return StatusCode(StatusCodes.Status500InternalServerError, "Erro interno no servidor.");
            }
        }

        /// <summary>
        /// Update
        /// </summary>
        /// <param name="id">An Id</param>
        /// <param name="usuarioExternoViewModel">A Usuario Externo View Model</param>
        /// <returns>An IActionResult.</returns>
        [HttpPut("{id:long}")]
        public IActionResult Update(long id, [FromBody] UsuarioExternoViewModel usuarioExternoViewModel)
        {
            try
            {
                if (id <= 0 || usuarioExternoViewModel == null)
                {
                    _logger.LogWarning("Tentativa de atualizar usuário com dados inválidos. ID: {id}", id);
                    return BadRequest("Dados inválidos.");
                }

                _logger.LogInformation("Tentando atualizar usuário com ID: {id}", id);
                bool sucesso = _usuarioExternoAppService.Update(usuarioExternoViewModel);

                if (!sucesso)
                {
                    _logger.LogWarning("Falha ao tentar atualizar usuário com ID {id}.", id);
                    return NotFound($"Usuário com ID {id} não encontrado.");
                }

                return NoContent(); // Retorna 204 No Content
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Erro ao tentar atualizar usuário com ID {id}.", id);
                return StatusCode(StatusCodes.Status500InternalServerError, "Erro interno no servidor.");
            }
        }

        /// <summary>
        /// Delete
        /// </summary>
        /// <param name="id">An Id</param>
        /// <returns>An IActionResult.</returns>
        [HttpDelete("{id:long}")]
        public IActionResult Delete(long id)
        {
            try
            {
                if (id <= 0)
                {
                    _logger.LogWarning("Tentativa de deletar usuário com ID inválido: {id}", id);
                    return BadRequest("ID inválido.");
                }

                _logger.LogInformation("Tentando deletar usuário com ID: {id}", id);
                bool sucesso = _usuarioExternoAppService.DeleteById(id);

                if (!sucesso)
                {
                    _logger.LogWarning("Usuário com ID {id} não encontrado para exclusão.", id);
                    return NotFound($"Usuário com ID {id} não encontrado.");
                }

                return NoContent(); // Retorna 204 No Content
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Erro ao tentar deletar usuário com ID {id}.", id);
                return StatusCode(StatusCodes.Status500InternalServerError, "Erro interno no servidor.");
            }
        }
    }
}
