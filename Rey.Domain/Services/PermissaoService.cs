using Rey.Domain.Entities;
using Rey.Domain.Interfaces.IRepository;
using Rey.Domain.Interfaces.IServices;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Rey.Domain.Services
{
    public class PermissaoService : IPermissaoExternoService
    {
         private readonly IPermissaoRepository _permissaoExternoRepository;

        public PermissaoService(IPermissaoRepository permissaoExternoRepository)
        {
            _permissaoExternoRepository = permissaoExternoRepository;
        }

        public Permissao CreateAndGet(Permissao perfil)
        {
            return _permissaoExternoRepository.CreateAndGet(perfil);
        }

        public bool DeleteById(long id)
        {
            return _permissaoExternoRepository.DeleteById(id);
        }

        public List<Permissao> GetAll()
        {
            return _permissaoExternoRepository.GetAll();
        }

        public Permissao GetById(long id)
        {
            return _permissaoExternoRepository.GetById(id);
        }

        public List<Permissao> GetByPermissionName(string name)
        {
            return _permissaoExternoRepository.GetByPermissionName(name);
        }

        public bool Update(Permissao perfilExterno)
        {
            return _permissaoExternoRepository.Update(perfilExterno);
        }
    }
}
