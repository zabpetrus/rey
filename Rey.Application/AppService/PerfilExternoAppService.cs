using AutoMapper;
using Microsoft.Extensions.Logging;
using Rey.Application.Interfaces;
using Rey.Application.ViewModel;
using Rey.Domain.Entities;
using Rey.Domain.Interfaces.IServices;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Rey.Application.AppService
{
    public class PerfilExternoAppService : IPerfilExternoAppService
    {
        private readonly IPerfilExternoService _perfilExternoService;
        private readonly ILogger<PerfilExternoAppService> _logger;
        private readonly IMapper _mapper;

        public PerfilExternoAppService(IPerfilExternoService perfilExternoService, ILogger<PerfilExternoAppService> logger, IMapper mapper)
        {
            _perfilExternoService = perfilExternoService;
           _logger = logger;
            _mapper = mapper;
        }

        public PerfilExternoViewModel CreateAndGet(PerfilExternoViewModel perfilExternoViewModel)
        {
           var perfil = _mapper.Map<PerfilExterno>(perfilExternoViewModel);
           var created = _perfilExternoService.CreateAndGet(perfil);
           return _mapper.Map<PerfilExternoViewModel>(created);
        }

        public bool DeleteById(long id)
        {
            bool response = _perfilExternoService.DeleteById(id);
            return response;
        }

        public List<PerfilExternoViewModel> GetAll()
        {
            List<PerfilExterno> lista = _perfilExternoService.GetAll();
            return _mapper.Map<List<PerfilExternoViewModel>>(lista);
        }

        public PerfilExternoViewModel GetById(long id)
        {
            PerfilExterno selecionado = _perfilExternoService.GetById(id);  
            return _mapper.Map<PerfilExternoViewModel>(selecionado);
        }

        public bool Update(PerfilExternoViewModel perfilExternoViewModel)
        {
            PerfilExterno perfil = _mapper.Map<PerfilExterno>(perfilExternoViewModel);
            bool selecionado = _perfilExternoService.Update(perfil);
            return selecionado;
        }
    }
}
