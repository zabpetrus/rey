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

        private readonly IPerfilRepository _perfilExternoRepository;

        public PerfilExternoService(IPerfilRepository perfilExternoRepository)
        {
            _perfilExternoRepository = perfilExternoRepository;
        }

        public Perfil CreateAndGet(Perfil perfil)
        {
            return   _perfilExternoRepository.CreateAndGet(perfil);
        }
                  
        public bool DeleteById(long id)
        {
            return _perfilExternoRepository.DeleteById(id);
        }

        public List<Perfil> GetAll()
        {
            return _perfilExternoRepository.GetAll();
        }

        public Perfil GetById(long id)
        {
            return _perfilExternoRepository.GetById(id);
        }

        public Task<Perfil> GetByIdAsync(long perfilId)
        {
            throw new NotImplementedException();
        }

        public bool Update(Perfil perfilExternoViewModel)
        {
           return _perfilExternoRepository.Update(perfilExternoViewModel);  
        }
    }
}
