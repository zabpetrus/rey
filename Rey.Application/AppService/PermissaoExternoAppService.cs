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
    }                        
}                        
