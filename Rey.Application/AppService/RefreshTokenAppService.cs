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
    public class RefreshTokenAppService  : IRefreshTokenAppService
    {
        private readonly IRefreshTokenExternoService _refreshtokenservice;
        private readonly IMapper _mapper;
        private readonly ILogger<RefreshTokenAppService> _logger;

    }
}
