using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc.Rendering;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Rey.Application.AppService;
using Rey.Application.Interfaces;
using Rey.Domain.Interfaces.IRepository;
using Rey.Domain.Interfaces.IServices;
using Rey.Domain.Services;
using Rey.Infra.Data.Context;
using Rey.Infra.Data.Repository;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Rey.Infra.Security.DI
{
    public class DependencyInjectionService
    {
        public static void RegisterDependencies(IConfiguration configuration, IServiceCollection services)
        {
            RegisterDatabase(configuration, services);
            RegisterRepositories(services);
            RegisterServices(services);
            RegisterApplicationServices(services);
            RegisterInfrastructures(services);
        }

        private static void RegisterDatabase(IConfiguration configuration, IServiceCollection services)
        {
            
            if (configuration.GetSection("DatabaseProvider").Value == "PostgreSQL")
            {
                var conexao2 = configuration.GetConnectionString("SecondConnection");
                services.AddDbContextPool<ApplicationDbContext>(options => options.UseNpgsql(conexao2));
            }

            else if (configuration.GetSection("DatabaseProvider").Value == "SQLServer")
            {
                var conexao = configuration.GetConnectionString("DefaultConnection");
                services.AddDbContextPool<ApplicationDbContext>(options => options.UseSqlServer(conexao));
            }
            else
            {
                throw new InvalidOperationException("Provider de banco de dados não suportado ou não especificado.");
            }            

        }
        private static void RegisterApplicationServices(IServiceCollection services)
        {
            services.AddScoped(typeof(IAuthenticatorService), typeof(AuthenticatorService));
            services.AddScoped<IUsuarioExternoAppService, UsuarioExternoAppService>(); 
            services.AddScoped<IPerfilExternoAppService, PerfilExternoAppService>();
            services.AddScoped<IRefreshTokenAppService,RefreshTokenAppService>();

        }


        private static void RegisterServices(IServiceCollection services)
        {
            services.AddScoped<ITokenService, TokenService>();
            services.AddScoped<IPerfilExternoService, PerfilExternoService>();
            services.AddScoped<IPermissaoExternoService, PermissaoExternoService>();
            services.AddScoped<IRefreshTokenExternoService,  RefreshTokenExternoService>();
            services.AddScoped<IUsuarioExternoService, UsuarioExternoService>();  
          
        }
        private static void RegisterRepositories(IServiceCollection services)
        {

            services.AddScoped<IPerfilExternoRepository, PerfilExternoRepository>();
            services.AddScoped<IPermissaoExternoRepository, PermissaoExternoRepository>();
            services.AddScoped<IRefreshTokenExternoRepository, RefreshTokenExternoRepository>();
            services.AddScoped<IUsuarioExternoRepository, UsuarioExternoRepository>();

        }
        private static void RegisterInfrastructures(IServiceCollection services)
        {
            services.TryAddSingleton<IHttpContextAccessor, HttpContextAccessor>(); //
            //services.AddScoped(typeof(Amazon.Interface.IImportacaoPedidoAmazonService), typeof(ImportacaoPedidoAmazonService));
        }

    }
}
