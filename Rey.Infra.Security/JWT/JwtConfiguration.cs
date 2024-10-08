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

            // Obtenha a seção JwtSettings do appsettings.json
            var jwtsettings = configuration.GetSection("JWTKey");

            // Obtenha a chave secreta da seção Auth
            var secretkey = jwtsettings["Secret"];

            // Codifique a chave secreta como bytes
            var encodedkey = Encoding.UTF8.GetBytes(secretkey);



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

                   ValidIssuer = jwtsettings["validIssuer"],
                   ValidAudience = jwtsettings["validAudience"],
                   IssuerSigningKey = new SymmetricSecurityKey(encodedkey)
               };
            });

        }
    }
}
