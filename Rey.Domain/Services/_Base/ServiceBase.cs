using Flunt.Notifications;
using Rey.Domain.Entities._Base;
using Rey.Domain.Interfaces.IServices._Base;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Rey.Domain.Services._Base
{
    public class ServiceBase<TEntity> : Notifiable<Notification>, IServiceBase<TEntity> where TEntity : Entity

    {
    }
}
