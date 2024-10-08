using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Rey.Application.ViewModel
{
    public class ResetPasswordViewModel
    {
        [Required]
        public string Email { get; set; }
        public string Token { get; set; }
        public string NovaSenha { get; set; }
    }
}
