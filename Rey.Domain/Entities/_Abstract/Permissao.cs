using Rey.Domain.Entities._Base;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Rey.Domain.Entities._Abstract
{
    //Claim
    public abstract class Permissao : Entity
    {
        public string Nome { get; set; }

    }
}
