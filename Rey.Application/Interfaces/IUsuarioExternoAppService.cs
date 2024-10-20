﻿using Rey.Application.ViewModel;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Rey.Application.Interfaces
{
    public interface IUsuarioExternoAppService
    {
        Task<UsuarioExternoViewModel> CreateAndGetAsync(UsuarioExternoViewModel usuarioExternoViewModel);
        Task<bool> CreateUserProfile(UsuarioPerfilViewModel request);
        Task<bool> DeleteById(long id);
        UsuarioExternoViewModel FindUserByCpf(string cpf);
        Task<List<UsuarioExternoViewModel>> GetAll();
        UsuarioExternoViewModel GetById(long id);
        Task<bool> Update(UsuarioExternoViewModel usuarioExternoViewModel);
    }
}
