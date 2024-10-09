using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Rey.Application.Interfaces;
using Rey.Application.ViewModel;
using System;
using System.Collections.Generic;

namespace Rey.Api.Controllers
{
    /// <summary>
    /// Permissões Externas Controller
    /// Equivalente à criação das Claims do Identity.
    /// </summary>
    [Route("api/[controller]")]
    [ApiController]
    public class PermissaoExternaController : ControllerBase
    {
        private readonly IHttpContextAccessor _contextAccessor;
        private readonly IPermissaoExternoAppService _permissaoAppService;
        private readonly ILogger<PermissaoExternaController> _logger;

        public PermissaoExternaController(
            IHttpContextAccessor contextAccessor,
            IPermissaoExternoAppService permissaoAppService,
            ILogger<PermissaoExternaController> logger)
        {
            _contextAccessor = contextAccessor;
            _permissaoAppService = permissaoAppService;
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
                var lista = _permissaoAppService.GetAll();
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
                var permissao = _permissaoAppService.GetById(id);

                if (permissao == null)
                {
                    _logger.LogWarning("Permissão com ID {id} não encontrada.", id);
                    return NotFound($"Permissão com ID {id} não encontrada.");
                }

                return Ok(permissao);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Erro ao tentar obter permissão por ID {id}.", id);
                return StatusCode(StatusCodes.Status500InternalServerError, "Erro interno no servidor.");
            }
        }
        /// <summary>
        /// Get By Permission Name
        /// </summary>
        /// <param name="name">A Name</param>
        /// <returns>An IActionResult.</returns>
        [HttpGet("name/{name}")]
        public IActionResult GetByPermissionName(string name)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(name))
                {
                    _logger.LogWarning("Nome de permissão inválido fornecido.");
                    return BadRequest("Nome de permissão inválido.");
                }

                _logger.LogInformation("Tentando obter permissões pelo nome: {name}", name);
                var lista = _permissaoAppService.GetByPermissionName(name);

                if (lista == null)
                {
                    _logger.LogWarning("Nenhuma permissão encontrada com o nome: {name}", name);
                    return NotFound($"Nenhuma permissão encontrada com o nome: {name}");
                }

                return Ok(lista);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Erro ao tentar obter permissões pelo nome {name}.", name);
                return StatusCode(StatusCodes.Status500InternalServerError, "Erro interno no servidor.");
            }
        }
        /// <summary>
        /// Create Permission
        /// </summary>
        /// <param name="permissaoExternaViewModel">A Permissao Externa View Model</param>
        /// <returns>An IActionResult.</returns>
        [HttpPost]
        public IActionResult CreatePermission([FromBody] PermissaoExternaViewModel permissaoExternaViewModel)
        {
            try
            {
                if (permissaoExternaViewModel == null)
                {
                    _logger.LogWarning("Tentativa de criar permissão com dados inválidos.");
                    return BadRequest("Dados inválidos.");
                }

                _logger.LogInformation("Tentando criar uma nova permissão.");
                var permissao = _permissaoAppService.CreateAndGet(permissaoExternaViewModel);
                return StatusCode(StatusCodes.Status201Created, permissao); // Retorna 201 Created com o objeto criado

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
        /// <param name="permissaoExternaViewModel">A Permissao Externa View Model</param>
        /// <returns>An IActionResult.</returns>
        [HttpPut("{id:long}")]
        public IActionResult Update(long id, [FromBody] PermissaoExternaViewModel permissaoExternaViewModel)
        {
            try
            {
                if (id <= 0 || permissaoExternaViewModel == null)
                {
                    _logger.LogWarning("Tentativa de atualizar permissão com dados inválidos. ID: {id}", id);
                    return BadRequest("Dados inválidos.");
                }

                _logger.LogInformation("Tentando atualizar permissão com ID: {id}", id);
                var sucesso = _permissaoAppService.Update(permissaoExternaViewModel);

                if (!sucesso)
                {
                    _logger.LogWarning("Falha ao tentar atualizar permissão com ID {id}.", id);
                    return NotFound($"Permissão com ID {id} não encontrada.");
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
                var sucesso = _permissaoAppService.DeleteById(id);

                if (!sucesso)
                {
                    _logger.LogWarning("Permissão com ID {id} não encontrada para exclusão.", id);
                    return NotFound($"Permissão com ID {id} não encontrada.");
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
