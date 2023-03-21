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
        private UserManager<Account> _userManager;
        private SignInManager<Account> _signInManager;

        public AuthenticationServices(UserManager<Account> userManager, SignInManager<Account> signInManager, IMongoDatabase mongoDb) : base(mongoDb)
        {
            _userManager = userManager;
            _signInManager = signInManager;
        }
    }
}
