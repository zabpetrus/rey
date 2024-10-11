
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
        public DbSet<UsuarioExterno> UsuariosExternos { get; set; }
        public DbSet<PerfilExterno> PerfisExternos { get; set; }
        public DbSet<PermissaoExterno> PermissoesExternas { get; set; }
        public DbSet<UsuarioPerfilExterno> UsuariosPerfisExternos { get; set; }
        public DbSet<PerfilPermissaoExterno> PerfisPermissoesExternos { get; set; }

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            modelBuilder.Entity<UsuarioPerfilExterno>()
                .HasKey(up => new { up.UsuarioId, up.PerfilId });

            modelBuilder.Entity<PerfilPermissaoExterno>()
                .HasKey(pp => new { pp.PerfilId, pp.PermissaoId });
        }


    }

}
