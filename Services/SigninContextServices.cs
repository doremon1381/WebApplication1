using AspNetCore.Identity.Mongo.Model;
using IdentityModel;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Identity;
using MongoDB.Driver;
using Serilog;
using System;
using System.Collections.Generic;
using System.Security.Claims;
using WebApplication1.Models;

namespace WebApplication1.Services
{
    public interface ISigninContextServices : IServices<Account>
    {
        Account GetByUserName(string contextUsername);
        Account GetByUserNameAndPassword(string contextUsername, string contextPassword);
        TokenResponse Create(Google.Apis.Auth.OAuth2.Responses.TokenResponse gToken);
        void SignIn(Account user);
    }

    /// <summary>
    /// Intent to use for user login, without google or facebook
    /// </summary>
    public class SigninContextServices : AbstractServices<Account, TokenResponse, MongoRole>, ISigninContextServices 
    {
        private IMongoCollection<Account> _account;
        private IMongoCollection<TokenResponse> _tokenResponse;
        private IMongoCollection<MongoRole> _role;
        private SignInManager<Account> _signInManager;

        public SigninContextServices(IMongoDatabase mongoDb, SignInManager<Account> signInManager, UserManager<Account> userManager) : base(mongoDb)
        {
            _account = _collection;
            _tokenResponse = _collection1;
            _role = _collection2;

            _signInManager = signInManager;
        }

        public Account Create(Account account)
        {
            try
            {
                var newAcc = new Account()
                {
                    //ID = _accounts.CountDocuments(new BsonDocument()) + 1,
                    UserName = account.UserName,
                    Email = account.Email,
                    Password = account.Password
                };
                _account.InsertOne(newAcc);

                // creating security context
                var claims = new List<Claim>
                {
                    new Claim(ClaimTypes.NameIdentifier, newAcc.UserName),
                    new Claim(ClaimTypes.Email, newAcc.Email)
                };
                var claimIdentity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
                var claimPrincipal = new ClaimsPrincipal(claimIdentity);

                return newAcc;
            }
            catch (System.Exception)
            {
                return null;
            }
        }

        public void Delete(string id)
        {
            throw new System.NotImplementedException();
        }

        public List<Account> Get()
        {
            var res = _account.Find(acc => true).ToList();
            return res;
        }

        public Account GetByUserName(string contextUsername)
        {
            //get your user model from db (by username - in my case its email)
            var acc = _account.Find(e => e.UserName.Equals(contextUsername)).First();
            if (string.IsNullOrEmpty(acc.SecurityStamp))
            {
                acc.SecurityStamp = Guid.NewGuid().ToString();
                // TODO: at this time, I need to manually create Security Stamp for technical problem, will check again
                _account.ReplaceOne(a => a.Id.Equals(acc.Id), acc);
            }
            return acc;
        }

        public Account GetByUserNameAndPassword(string contextUsername, string contextPassword)
        {
            //get your user model from db (by username - in my case its email)
            var acc = _account.Find(e => e.UserName.Equals(contextUsername) && e.Password.Equals(contextPassword)).First();
            if (string.IsNullOrEmpty(acc.SecurityStamp))
            {
                acc.SecurityStamp = Guid.NewGuid().ToString();
                // TODO: at this time, I need to manually create Security Stamp for technical problem, will check again
                _account.ReplaceOne(a => a.Id.Equals(acc.Id), acc);
            }

            return acc;
        }

        public Account GetById(string id)
        {
            var res = _account.Find(s => s.Id.Equals(id)).First();
            return res;
        }

        public Account Update(Account newAcc)
        {
            var old = _account.Find(s => s.Id.Equals(newAcc.Id)).First();

            // TODO:
            return old;
            //_accounts.UpdateOne(Builders<Account>.Filter.Eq(s => s.id, ObjectId.Parse(id)), newAcc);
        }

        public void SignIn(Account user)
        {
            try
            {
                //// signin, login, authen or anything like these
                //var createUser = _userManager.CreateAsync(user).Result;
                if (_role.EstimatedDocumentCount() == 0)
                {
                    _role.InsertOne(new MongoRole("admin"));
                }
                var admin = GetRole();
                // TODO: dont use asynchonous in this programaticaly function
                //var signinAsync = await _signInManager.SignInWithClaimsAsync(user, isPersistent: true, );
                var signin = _signInManager.SignInWithClaimsAsync(user, isPersistent: true, ManuallyCreateClaimsForUserIDentity(user, admin));
                var createUserClaim = _signInManager.CreateUserPrincipalAsync(user).Result;
                bool isSignIn = _signInManager.IsSignedIn(createUserClaim);
            }
            catch (System.Exception ex)
            {
                // TODO: write code for log action later
                //Log.Logger.BindMessageTemplate
                throw;
            }
        }

        private async void LogError()
        {

        }

        private MongoRole GetRole()
        {
            MongoRole role = new MongoRole();
            try
            {
                var current = _role.Find(r => r.Name.Equals("admin")).First();

                return role;
            }
            catch (Exception ex)
            {

                throw;
            }
        }

        /// <summary>
        /// Add new token of user's current session to db
        /// </summary>
        /// <param name="document"></param>
        /// <returns></returns>
        /// <exception cref="System.NotImplementedException"></exception>
        public TokenResponse Create(Google.Apis.Auth.OAuth2.Responses.TokenResponse gToken)
        {
            TokenResponse newToken = TokenResponse.MapWithGoogleTokenRespone(gToken);
            try
            {
                _tokenResponse.InsertOne(newToken);

                newToken = _tokenResponse.Find(t => t.AccessToken.Equals(gToken.AccessToken) && t.IdToken.Equals(gToken.IdToken)).First();
            }
            catch (System.Exception ex)
            {
                var ms = ex.Message;
                throw;
            }

            return newToken;
        }

        /// <summary>
        /// TODO: will check again
        /// build claims array from user data
        /// </summary>
        /// <param name="user"></param>
        /// <returns></returns>
        private List<Claim> ManuallyCreateClaimsForUserIDentity(Account user, MongoRole roles)
        {
            string role = roles.Id.ToString();

            var claims = new List<Claim>
            {
                new Claim("user_id", user.Id.ToString() ?? ""),
                new Claim(JwtClaimTypes.Name, !string.IsNullOrEmpty(user.UserName) ? user.UserName : ""),
                new Claim(JwtClaimTypes.Email, user.Email  ?? ""),
                new Claim("Facebook", user.Facebook  ?? ""),
                new Claim(JwtClaimTypes.PhoneNumber, user.PhoneNumber  ?? ""),
                //new Claim(JwtClaimTypes.Issuer, user),
                new Claim(JwtClaimTypes.Address, user.Address  ?? ""),
                new Claim(JwtClaimTypes.Role, role),
                new Claim("api", user.Apis[0]),
            };

            for (int i = 0; i < user.Apis.Count; i++)
            {
                claims.Add(new Claim("api", user.Apis[i]));
            }

            return claims;
        }

    }
}
