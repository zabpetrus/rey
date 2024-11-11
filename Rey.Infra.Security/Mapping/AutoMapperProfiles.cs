using AutoMapper;
using Rey.Application.ViewModel;
using Rey.Domain.Entities;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Rey.Infra.Security.Mapping
{
    public class AutoMapperProfiles : Profile
    {
        public AutoMapperProfiles()
        {
            // Definição dos mapeamentos aqui
            CreateMap<Usuario, UsuarioViewModel>();
            CreateMap<UsuarioViewModel, Usuario>();

            CreateMap<Perfil, PerfilViewModel>();
            CreateMap<PerfilViewModel, Perfil>();

            CreateMap<Permissao, PermissaoViewModel>();
            CreateMap<PermissaoViewModel, Permissao>();

            CreateMap<LoginRequestViewModel, Usuario>();
            

            CreateMap<RegisterViewModel, Usuario>();
            CreateMap<ResetPasswordViewModel, Usuario>();

        }


    }
}
