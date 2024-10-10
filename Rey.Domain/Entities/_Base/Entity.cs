using Microsoft.AspNetCore.Identity;
using System.ComponentModel.DataAnnotations;

namespace Rey.Domain.Entities._Base
{
    /**/
    public abstract class Entity
    {

        [Key]
        public long Id { get; set; }  

        public DateTime DataInclusao { get; set; } 

        public DateTime DataAlteracao { get; set; }

     
    }
}
