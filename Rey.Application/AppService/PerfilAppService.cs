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
    public class PerfilAppService : IPerfilAppService
    {
        private readonly IPerfilExternoService _perfilExternoService;
        private readonly ILogger<PerfilAppService> _logger;
        private readonly IMapper _mapper;

        public PerfilAppService(IPerfilExternoService perfilExternoService, ILogger<PerfilAppService> logger, IMapper mapper)
        {
            _perfilExternoService = perfilExternoService;
           _logger = logger;
            _mapper = mapper;
        }

        public PerfilViewModel CreateAndGet(PerfilViewModel perfilExternoViewModel)
        {
           var perfil = _mapper.Map<Perfil>(perfilExternoViewModel);
           var created = _perfilExternoService.CreateAndGet(perfil);
           return _mapper.Map<PerfilViewModel>(created);
        }

        public bool DeleteById(long id)
        {
            bool response = _perfilExternoService.DeleteById(id);
            return response;
        }

        public List<PerfilViewModel> GetAll()
        {
            List<Perfil> lista = _perfilExternoService.GetAll();
            return _mapper.Map<List<PerfilViewModel>>(lista);
        }

        public PerfilViewModel GetById(long id)
        {
            Perfil selecionado = _perfilExternoService.GetById(id);  
            return _mapper.Map<PerfilViewModel>(selecionado);
        }

        public bool Update(PerfilViewModel perfilExternoViewModel)
        {
            Perfil perfil = _mapper.Map<Perfil>(perfilExternoViewModel);
            bool selecionado = _perfilExternoService.Update(perfil);
            return selecionado;
        }
    }
}
