using AutoMapper;
using Microsoft.Extensions.Logging;
using Rey.Application.Interfaces;
using Rey.Application.ViewModel;
using Rey.Domain.Interfaces.IServices;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Rey.Application.AppService
{
    public class UsuarioExternoAppService : IUsuarioExternoAppService
    {
        private readonly IUsuarioExternoService _usuarioExternoService;
        private readonly IMapper _mapper;
        private readonly ILogger<UsuarioExternoAppService> _logger;

        public UsuarioExternoAppService(IUsuarioExternoService usuarioExternoService, IMapper mapper, ILogger<UsuarioExternoAppService> logger)
        {
            _usuarioExternoService = usuarioExternoService;
            _mapper = mapper;
            _logger = logger;
        }

        public UsuarioExternoViewModel CreateAndGet(UsuarioExternoViewModel permissaoExternaViewModel)
        {
            throw new NotImplementedException();
        }

        public bool DeleteById(long id)
        {
            throw new NotImplementedException();
        }

        public UsuarioExternoViewModel FindUserByCpf(string cpf)
        {
            var res = _usuarioExternoService.FindUserByCpf(cpf);
            return _mapper.Map<UsuarioExternoViewModel>(res);
        }

        public List<UsuarioExternoViewModel> GetAll()
        {
            throw new NotImplementedException();
        }

        public List<UsuarioExternoViewModel> GetById(long id)
        {
            throw new NotImplementedException();
        }

        public bool Update(UsuarioExternoViewModel permissaoExternaViewModel)
        {
            throw new NotImplementedException();
        }
    }
}
