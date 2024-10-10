using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Rey.Application.Interfaces;
using Rey.Application.ViewModel;
using System;
using System.Collections.Generic;

namespace Rey.Api.Controllers
{
    /// <summary>
    /// Perfis Externos Controller
    /// Equivalente à criação das Roles do Identity.
    /// </summary>
    [Route("api/[controller]")]
    [ApiController]
    public class PerfilExternoController : ControllerBase
    {
        private readonly IHttpContextAccessor _contextAccessor;
        private readonly IPerfilExternoAppService _perfilAppService;
        private readonly ILogger<PerfilExternoController> _logger;

        public PerfilExternoController(
            IHttpContextAccessor contextAccessor,
            IPerfilExternoAppService perfilAppService,
            ILogger<PerfilExternoController> logger)
        {
            _contextAccessor = contextAccessor;
            _perfilAppService = perfilAppService;
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
                _logger.LogInformation("Tentando obter todas as permissões.");
                List<PerfilExternoViewModel> lista = _perfilAppService.GetAll();
                if (lista == null)
                {
                    _logger.LogWarning("Nenhuma permissão encontrada.");
                    return NotFound("Nenhuma permissão encontrada.");
                }
                return Ok(lista);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Erro ao tentar obter todas as permissões.");
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

                _logger.LogInformation("Tentando obter permissão com ID: {id}", id);
                PerfilExternoViewModel perfil = _perfilAppService.GetById(id);

                if (perfil == null)
                {
                    _logger.LogWarning("Perfil com ID {id} não encontrada.", id);
                    return NotFound($"Perfil com ID {id} não encontrada.");
                }

                return Ok(perfil);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Erro ao tentar obter permissão por ID {id}.", id);
                return StatusCode(StatusCodes.Status500InternalServerError, "Erro interno no servidor.");
            }
        }
        
        /// <summary>
        /// Create Permission
        /// </summary>
        /// <param name="perfilExternoViewModel">A Perfil Externo View Model</param>
        /// <returns>An IActionResult.</returns>
        [HttpPost]
        public IActionResult Create([FromBody] PerfilExternoViewModel perfilExternoViewModel)
        {
            try
            {
                if (perfilExternoViewModel == null)
                {
                    _logger.LogWarning("Tentativa de criar permissão com dados inválidos.");
                    return BadRequest("Dados inválidos.");
                }

                _logger.LogInformation("Tentando criar uma nova permissão.");
                PerfilExternoViewModel perfil = _perfilAppService.CreateAndGet(perfilExternoViewModel);
                return StatusCode(StatusCodes.Status201Created, perfil); // Retorna 201 Created com o objeto criado

            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Erro ao tentar criar uma nova permissão.");
                return StatusCode(StatusCodes.Status500InternalServerError, "Erro interno no servidor.");
            }
        }
        /// <summary>
        /// Update
        /// </summary>
        /// <param name="id">An Id</param>
        /// <param name="perfilExternoViewModel">A Perfil Externo View Model</param>
        /// <returns>An IActionResult.</returns>
        [HttpPut("{id:long}")]
        public IActionResult Update(long id, [FromBody] PerfilExternoViewModel perfilExternoViewModel)
        {
            try
            {
                if (id <= 0 || perfilExternoViewModel == null)
                {
                    _logger.LogWarning("Tentativa de atualizar permissão com dados inválidos. ID: {id}", id);
                    return BadRequest("Dados inválidos.");
                }

                _logger.LogInformation("Tentando atualizar permissão com ID: {id}", id);
                bool sucesso = _perfilAppService.Update(perfilExternoViewModel);

                if (!sucesso)
                {
                    _logger.LogWarning("Falha ao tentar atualizar permissão com ID {id}.", id);
                    return NotFound($"Perfil com ID {id} não encontrada.");
                }

                return NoContent(); // Retorna 204 No Content
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Erro ao tentar atualizar permissão com ID {id}.", id);
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
                    _logger.LogWarning("Tentativa de deletar permissão com ID inválido: {id}", id);
                    return BadRequest("ID inválido.");
                }

                _logger.LogInformation("Tentando deletar permissão com ID: {id}", id);
                bool sucesso = _perfilAppService.DeleteById(id);

                if (!sucesso)
                {
                    _logger.LogWarning("Perfil com ID {id} não encontrada para exclusão.", id);
                    return NotFound($"Perfil com ID {id} não encontrada.");
                }

                return NoContent(); // Retorna 204 No Content
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Erro ao tentar deletar permissão com ID {id}.", id);
                return StatusCode(StatusCodes.Status500InternalServerError, "Erro interno no servidor.");
            }
        }
    }
}
