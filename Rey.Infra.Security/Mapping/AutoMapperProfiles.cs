﻿using AutoMapper;
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
            CreateMap<UsuarioExterno, UsuarioExternoViewModel>();
            CreateMap<UsuarioExternoViewModel, UsuarioExterno>();
            CreateMap<PerfilExterno, PerfilExternoViewModel>();
            CreateMap<PerfilExternoViewModel, PerfilExterno>();
            CreateMap<LoginRequestViewModel, UsuarioExterno>()
            .ForMember(dest => dest.HashSenha, opt => opt.Ignore()); 

            CreateMap<RegisterViewModel, UsuarioExterno>();
            CreateMap<ResetPasswordViewModel, UsuarioExterno>();

        }


    }
}
