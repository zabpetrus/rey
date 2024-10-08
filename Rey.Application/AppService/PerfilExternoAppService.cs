using AutoMapper;
using Microsoft.Extensions.Logging;
using Rey.Application.Interfaces;
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
    }
}
