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
    public class PerfilExternoService : IPerfilExternoService
    {

        private readonly IPerfilExternoRepository _perfilExternoRepository;

        public PerfilExternoService(IPerfilExternoRepository perfilExternoRepository)
        {
            _perfilExternoRepository = perfilExternoRepository;
        }

        public PerfilExterno CreateAndGet(PerfilExterno perfil)
        {
            return   _perfilExternoRepository.CreateAndGet(perfil);
        }
                  
        public bool DeleteById(long id)
        {
            return _perfilExternoRepository.DeleteById(id);
        }

        public List<PerfilExterno> GetAll()
        {
            return _perfilExternoRepository.GetAll();
        }

        public PerfilExterno GetById(long id)
        {
            return _perfilExternoRepository.GetById(id);
        }

        public Task<PerfilExterno> GetByIdAsync(long perfilId)
        {
            throw new NotImplementedException();
        }

        public bool Update(PerfilExterno perfilExternoViewModel)
        {
           return _perfilExternoRepository.Update(perfilExternoViewModel);  
        }
    }
}
