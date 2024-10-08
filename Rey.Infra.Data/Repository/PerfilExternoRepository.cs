using Rey.Domain.Entities;
using Rey.Domain.Interfaces.IRepository;
using Rey.Infra.Data.Context;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Rey.Infra.Data.Repository
{
    public class PerfilExternoRepository: IPerfilExternoRepository
    {
        private readonly ApplicationDbContext _context;

        public PerfilExternoRepository(ApplicationDbContext context)
        {
            _context = context;
        }

        public List<PermissaoExterno> ObterPermissoesDePerfil(int perfilId)
        {
            var permissoes = (from pp in _context.PerfisPermissoesExternos
                              join pe in _context.PermissoesExternas on pp.PermissaoId equals pe.Id
                              where pp.PerfilId == perfilId
                              select pe).ToList();

            return permissoes;
        }
    }
}
