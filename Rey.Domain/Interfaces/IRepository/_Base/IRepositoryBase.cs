using Rey.Domain.Entities._Base;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Rey.Domain.Interfaces.IRepository._Base
{
    public interface IRepositoryBase<TEntity> where TEntity : Entity
    {
    }
}
