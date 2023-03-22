using Microsoft.AspNetCore.Identity;
using MongoDB.Driver;
using System.Collections.Generic;
using WebApplication1.Models;

namespace WebApplication1.Services
{
    public interface IAuthenticationServices 
        //: IServices<TokenResponse>
    {

    }

    /// <summary>
    /// intent to use for google or facebook
    /// </summary>
    public class AuthenticationServices : AbstractServices<TokenResponse>, IAuthenticationServices
    {
        private UserManager<CurrentIdentityUser> _userManager;
        private SignInManager<CurrentIdentityUser> _signInManager;

        public AuthenticationServices(UserManager<CurrentIdentityUser> userManager, SignInManager<CurrentIdentityUser> signInManager, IMongoDatabase mongoDb) : base(mongoDb)
        {
            _userManager = userManager;
            _signInManager = signInManager;
        }
    }
}
