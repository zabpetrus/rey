using Rey.Domain.Entities;
using Rey.Domain.Interfaces.IRepository;
using Rey.Infra.Data.Context;
using System;
using System.Collections.Generic;
using System.Linq;

namespace Rey.Infra.Data.Repository
{
    public class PerfilRepository : IPerfilRepository
    {
        private readonly ApplicationDbContext _context;

        public PerfilRepository(ApplicationDbContext context)
        {
            _context = context;
        }

        public Perfil CreateAndGet(Perfil perfil)
        {
            _context.PerfisExternos.Add(perfil);
            _context.SaveChanges();  
            return perfil; 
        }

        public bool DeleteById(long id)
        {
            var perfil = _context.PerfisExternos.Find(id);
            if (perfil == null) return false; 

            _context.PerfisExternos.Remove(perfil);
            _context.SaveChanges();  
            return true;
        }

        public List<Perfil> GetAll()
        {
            return _context.PerfisExternos.ToList();  
        }

        public Perfil GetById(long id)
        {
            return _context.PerfisExternos.Find(id);  
        }

        public List<Permissao> ObterPermissoesDePerfil(int perfilId)
        {
            var permissoes = (from pp in _context.PerfisPermissoesExternos
                              join pe in _context.PermissoesExternas on pp.PermissaoId equals pe.Id
                              where pp.PerfilId == perfilId
                              select pe).ToList();

            return permissoes;  // Retorna a lista de permissões associadas ao perfil.
        }

        public bool Update(Perfil perfilExterno)
        {
            _context.PerfisExternos.Update(perfilExterno);
            _context.SaveChanges();  // Salva as mudanças no banco de dados.
            return true;  // Retorna verdadeiro indicando que a operação foi bem-sucedida.
        }
    }
}
