﻿using Rey.Application.ViewModel;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Rey.Application.Interfaces
{
    public interface IPerfilAppService
    {
        PerfilViewModel CreateAndGet(PerfilViewModel perfilExternoViewModel);
        bool DeleteById(long id);
        List<PerfilViewModel> GetAll();
        PerfilViewModel GetById(long id);
        bool Update(PerfilViewModel perfilExternoViewModel);
    }
}
