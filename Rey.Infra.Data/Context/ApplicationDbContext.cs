
using AutoMapper;
using Microsoft.EntityFrameworkCore;
using Rey.Domain.Entities;
using Rey.Domain.Entities.Auth;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security;
using System.Text;
using System.Threading.Tasks;

namespace Rey.Infra.Data.Context
{
    public class ApplicationDbContext : DbContext
    {
        public ApplicationDbContext(DbContextOptions dbContextOptions) : base(dbContextOptions)
        {
        }

        public DbSet<RefreshToken> RefreshTokens { get; set; }
        public DbSet<Usuario> UsuariosExternos { get; set; }
        public DbSet<Perfil> PerfisExternos { get; set; }
        public DbSet<Permissao> PermissoesExternas { get; set; }
        public DbSet<UsuarioPerfil> UsuariosPerfisExternos { get; set; }
        public DbSet<PerfilPermissao> PerfisPermissoesExternos { get; set; }

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            modelBuilder.Entity<UsuarioPerfil>()
                .HasKey(up => new { up.UsuarioId, up.PerfilId });

            modelBuilder.Entity<PerfilPermissao>()
                .HasKey(pp => new { pp.PerfilId, pp.PermissaoId });
        }


    }

}
