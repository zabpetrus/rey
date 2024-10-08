﻿using Rey.Domain.Entities;
using Rey.Domain.Interfaces.IRepository;
using Rey.Infra.Data.Context;

namespace Rey.Infra.Data.Repository
{
    public class PermissaoExternoRepository : IPermissaoExternoRepository
    {
         private readonly ApplicationDbContext _context;

        public PermissaoExternoRepository(ApplicationDbContext context)
        {
            _context = context;
        }


        public List<PerfilExterno> ObterPerfisDeUsuario(int usuarioId)
        {
           
           var perfis2 = _context.PermissoesExternas.Select(e => e.Id == usuarioId).ToList(); 
           var perfis = (from up in _context.UsuariosPerfisExternos
                          join p in _context.PerfisExternos on up.PerfilId equals p.Id
                          where up.UsuarioId == usuarioId
                          select p).ToList();  

            return perfis;
        }

        public List<PermissaoExterno> RetrievePermissionsByProfile(PerfilExterno perfil)
        {
            // Verifica se o perfil é nulo
            if (perfil == null)
                throw new ArgumentNullException(nameof(perfil));

            // Obtém os PermissaoIds associados ao PerfilId a partir da tabela de junção PerfisPermissao
            var permissaoIds = _context.PerfisPermissoesExternos
                                .Where(pp => pp.PerfilId == perfil.Id) // Filtra pela ID do perfil
                                .Select(pp => pp.PermissaoId) // Seleciona os IDs das permissões
                                .ToList(); // Converte para uma lista

            // Busca as PermissoesExternas usando os IDs coletados
            var permissoes = _context.PermissoesExternas
                                .Where(p => permissaoIds.Contains(p.Id)) // Filtra permissões com base nos IDs
                                .ToList(); // Converte para uma lista e retorna

            return permissoes; // Retorna a lista de PermissaoExterno
        }

    }
}
