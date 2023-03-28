using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using MongoDB.Driver;
using System.Linq;
using WebApplication1.Models.IdentityServer4;
using WebApplication1.Services.Base;

namespace WebApplication1.Services
{

    /// <summary>
    /// Intent to use for IS4, for identity
    /// Different with appserver's login User
    /// </summary>
    public class AuthenticationServices : AbstractServices<CurrentIdentityUser, TokenResponse, CurrentIdentityRole, CurrentUserClaim>
    {
        public AuthenticationServices(IMongoDatabase mongoDb, HttpContextAccessor httpContextAccessor, 
            SignInManager<CurrentIdentityUser> signInManager, UserManager<CurrentIdentityUser> userManager, RoleManager<CurrentIdentityRole> roleManager) 
            : base(mongoDb)
        {
            //_role = _collection2;
            //_identityClaim = _collection3;
        }
    }
}
