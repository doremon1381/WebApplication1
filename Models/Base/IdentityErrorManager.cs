using Microsoft.AspNetCore.Identity;
using System.Collections.Generic;

namespace WebApplication1.Models.Base
{
    public static class IdentityErrorManager
    {
        private static readonly Dictionary<int, IdentityError> errors = new Dictionary<int, IdentityError>()
        {
            { 
                1, new IdentityError()
                    {
                        Code = "PasswordRequiresNonAlphanumeric",
                        Description = "Passwords must have at least one non alphanumeric character."
                    }
            },
            {
                2, new IdentityError()
                    {
                        Code= "PasswordRequiresLower",
                        Description = "Passwords must have at least one lowercase ('a'-'z')."
                    }
            }
            ,
            {
                3, new IdentityError()
                    {
                        Code= "PasswordRequiresUpper",
                        Description = "Passwords must have at least one uppercase ('A'-'Z')."
                    }
            }
        };

        public static IdentityError PasswordRequiresNonAlphanumeric => errors[1];
        public static IdentityError PasswordRequiresLower => errors[2];
        public static IdentityError PasswordRequiresUpper => errors[3];
    }
}
