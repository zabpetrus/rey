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
    public class PermissaoExternoAppService : IPermissaoExternoAppService
    {
        private readonly IPermissaoExternoService _permissaoExternoService;
        private readonly IMapper _mapper;
        private readonly ILogger<PermissaoExternoAppService> _logger;

        public PermissaoExternoAppService(IPermissaoExternoService permissaoExternoService, IMapper mapper, ILogger<PermissaoExternoAppService> logger)
        {
            _permissaoExternoService = permissaoExternoService;
            _mapper = mapper;
            _logger = logger;
        }

        public PermissaoExternaViewModel CreateAndGet(PermissaoExternaViewModel permissaoExternaViewModel)
        {
            var perfil = _mapper.Map<PermissaoExterno>(permissaoExternaViewModel);
            var created = _permissaoExternoService.CreateAndGet(perfil);
            return _mapper.Map<PermissaoExternaViewModel>(created);
        }

        public bool DeleteById(long id)
        {
            bool response = _permissaoExternoService.DeleteById(id);
            return response;
        }

        public List<PermissaoExternaViewModel> GetAll()
        {
            List<PermissaoExterno> lista = _permissaoExternoService.GetAll();
            return _mapper.Map<List<PermissaoExternaViewModel>>(lista);
        }

        public PermissaoExternaViewModel GetById(long id)
        {
            PermissaoExterno selecionado = _permissaoExternoService.GetById(id);
            return _mapper.Map<PermissaoExternaViewModel>(selecionado);
        }

        public List<PermissaoExternaViewModel> GetByPermissionName(string name)
        {
            List<PermissaoExterno> selecionado = _permissaoExternoService.GetByPermissionName(name);
            return _mapper.Map<List<PermissaoExternaViewModel>>(selecionado);
        }

        public bool Update(PermissaoExternaViewModel permissaoExternaViewModel)
        {
            PermissaoExterno perfil = _mapper.Map<PermissaoExterno>(permissaoExternaViewModel);
            bool selecionado = _permissaoExternoService.Update(perfil);
            return selecionado;
        }
    }                        
}                        
