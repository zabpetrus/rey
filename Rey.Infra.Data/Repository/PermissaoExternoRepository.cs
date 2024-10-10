using Microsoft.EntityFrameworkCore.ChangeTracking;
using Rey.Domain.Entities;
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

        public PermissaoExterno CreateAndGet(PermissaoExterno perfil)
        {
            EntityEntry<PermissaoExterno> ops = _context.PermissoesExternas.Add(perfil);

            if (ops == null)
            {
                throw new InvalidOperationException("Erro na inserção");
            }

            _context.SaveChanges();

            return ops.Entity;

        }

        public bool DeleteById(long id)
        {
            // Busca a permissão pelo ID
            var permissao = _context.PermissoesExternas.Find(id);

            if (permissao == null)
                return false; // Se não encontrar, retorna falso

            // Remove a permissão
            _context.PermissoesExternas.Remove(permissao);

            // Salva as mudanças no banco de dados
            _context.SaveChanges();

            return true; // Retorna verdadeiro indicando que a exclusão foi bem-sucedida
        }

        public List<PermissaoExterno> GetAll()
        {
            return _context.PermissoesExternas.ToList();
        }

        public PermissaoExterno GetById(long id)
        {
            return _context.PermissoesExternas.Find(id);
        }

        public List<PermissaoExterno> GetByPermissionName(string name)
        {
            return _context.PermissoesExternas
                 .Where(p => p.Nome == name)
                 .ToList();
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

        public bool Update(PermissaoExterno perfilExternoViewModel)
        {
            if (perfilExternoViewModel == null)
                return false;

            // Atualiza a permissão no contexto
            _context.PermissoesExternas.Update(perfilExternoViewModel);

            // Salva as mudanças no banco de dados
            _context.SaveChanges();

            return true; // Retorna verdadeiro indicando que a atualização foi bem-sucedida
        }
    }
}
