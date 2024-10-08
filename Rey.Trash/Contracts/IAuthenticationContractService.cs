using Microsoft.AspNetCore.Identity;
using Rey.Trash.Dto;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Rey.Trash.Contracts
{
    public interface IAuthenticationContractService
    {
        Task<IdentityResult> RegisterUser(UserForRegistrationDto userForRegistration);
        Task<bool> ValidateUser(UserForRegistrationDto userForRegistration);
        Task<TokenDto> CreateToken(bool populateExp);
    }
}
