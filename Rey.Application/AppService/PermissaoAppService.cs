using AutoMapper;
using Microsoft.Extensions.Logging;
using Rey.Application.Interfaces;
using Rey.Application.ViewModel;
using Rey.Domain.Entities;
using Rey.Domain.Interfaces.IServices;
using Rey.Domain.Services;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Rey.Application.AppService
{
    public class PermissaoAppService : IPermissaoAppService
    {
        private readonly IPermissaoExternoService _permissaoExternoService;
        private readonly IMapper _mapper;
        private readonly ILogger<PermissaoAppService> _logger;

        public PermissaoAppService(IPermissaoExternoService permissaoExternoService, IMapper mapper, ILogger<PermissaoAppService> logger)
        {
            _permissaoExternoService = permissaoExternoService;
            _mapper = mapper;
            _logger = logger;
        }

        public PermissaoViewModel CreateAndGet(PermissaoViewModel permissaoExternaViewModel)
        {
            var perfil = _mapper.Map<Permissao>(permissaoExternaViewModel);
            var created = _permissaoExternoService.CreateAndGet(perfil);
            return _mapper.Map<PermissaoViewModel>(created);
        }

        public bool DeleteById(long id)
        {
            bool response = _permissaoExternoService.DeleteById(id);
            return response;
        }

        public List<PermissaoViewModel> GetAll()
        {
            List<Permissao> lista = _permissaoExternoService.GetAll();
            return _mapper.Map<List<PermissaoViewModel>>(lista);
        }

        public PermissaoViewModel GetById(long id)
        {
            Permissao selecionado = _permissaoExternoService.GetById(id);
            return _mapper.Map<PermissaoViewModel>(selecionado);
        }

        public List<PermissaoViewModel> GetByPermissionName(string name)
        {
            List<Permissao> selecionado = _permissaoExternoService.GetByPermissionName(name);
            return _mapper.Map<List<PermissaoViewModel>>(selecionado);
        }

        public bool Update(PermissaoViewModel permissaoExternaViewModel)
        {
            Permissao perfil = _mapper.Map<Permissao>(permissaoExternaViewModel);
            bool selecionado = _permissaoExternoService.Update(perfil);
            return selecionado;
        }
    }                        
}                        
