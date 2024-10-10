using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Rey.Infra.Security.JWT
{
    public class JwtConfiguration
    {
        public static void JwtServices(IConfiguration configuration, IServiceCollection services)
        {
            RegisterJwtServices(services, configuration);
        }

        private static void RegisterJwtServices(IServiceCollection services, IConfiguration configuration)
        {
            // Obtenha a seção JWTSettings do appsettings.json
            IConfigurationSection jwtsettings = configuration.GetSection("JWTSettings");

            // Obtenha a chave secreta da seção JWTSettings
            string secretkey = jwtsettings["Secret"];

            // Verifique se a chave secreta é nula ou vazia
            if (string.IsNullOrEmpty(secretkey))
            {
                throw new ArgumentNullException("A chave secreta JWT não está configurada. Verifique a configuração no appsettings.json.");
            }

            // Codifique a chave secreta como bytes
            byte[] encodedkey = Encoding.UTF8.GetBytes(secretkey);

            services.AddAuthentication(opt =>
            {
                opt.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
                opt.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
            })
            .AddJwtBearer(options =>
            {
                options.TokenValidationParameters = new TokenValidationParameters
                {
                    ValidateIssuer = true,
                    ValidateAudience = true,
                    ValidateLifetime = true,
                    ValidateIssuerSigningKey = true,

                    ValidIssuer = jwtsettings["ValidIssuer"],
                    ValidAudience = jwtsettings["ValidAudience"],
                    IssuerSigningKey = new SymmetricSecurityKey(encodedkey)
                };
            });
        }

    }
}
