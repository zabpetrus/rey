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
    public class PermissaoExternoService : IPermissaoExternoService
    {
         private readonly IPermissaoExternoRepository _permissaoExternoRepository;

        public PermissaoExternoService(IPermissaoExternoRepository permissaoExternoRepository)
        {
            _permissaoExternoRepository = permissaoExternoRepository;
        }

        public PermissaoExterno CreateAndGet(PermissaoExterno perfil)
        {
            return _permissaoExternoRepository.CreateAndGet(perfil);
        }

        public bool DeleteById(long id)
        {
            return _permissaoExternoRepository.DeleteById(id);
        }

        public List<PermissaoExterno> GetAll()
        {
            return _permissaoExternoRepository.GetAll();
        }

        public PermissaoExterno GetById(long id)
        {
            return _permissaoExternoRepository.GetById(id);
        }

        public List<PermissaoExterno> GetByPermissionName(string name)
        {
            return _permissaoExternoRepository.GetByPermissionName(name);
        }

        public bool Update(PermissaoExterno perfilExterno)
        {
            return _permissaoExternoRepository.Update(perfilExterno);
        }
    }
}
