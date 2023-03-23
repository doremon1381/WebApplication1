using IdentityModel;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Authentication;
using MongoDB.Driver;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using WebApplication1.Models.IdentityServer4;
using WebApplication1.Services.Base;

namespace WebApplication1.Services
{
    public interface IAuthenticationServices : IServices<CurrentIdentityUser>
    {
        CurrentIdentityUser GetIdentityUserByName(string contextUsername);
        CurrentIdentityUser GetIdentityUserByNameAndPassword(string contextUsername, string contextPassword);
        CurrentIdentityUser CreateNewIdentityUser(string userName,string password);
        TokenResponse Create(Google.Apis.Auth.OAuth2.Responses.TokenResponse gToken);
        CurrentIdentityUser GetIdentityUser(CurrentIdentityUser identity);
    }

    /// <summary>
    /// Intent to use for IS4, for identity
    /// Different with appserver's login User
    /// </summary>
    public class AuthenticationServices : AbstractServices<CurrentIdentityUser, TokenResponse, CurrentIdentityRole, CurrentUserClaim>, IAuthenticationServices
    {
        private IMongoCollection<CurrentIdentityUser> _identityUser;
        private IMongoCollection<TokenResponse> _tokenResponse;
        private IMongoCollection<CurrentIdentityRole> _role;
        private IMongoCollection<CurrentUserClaim> _identityClaim;

        public AuthenticationServices(IMongoDatabase mongoDb, HttpContextAccessor httpContextAccessor, 
            SignInManager<CurrentIdentityUser> signInManager, UserManager<CurrentIdentityUser> userManager, RoleManager<CurrentIdentityRole> roleManager) 
            : base(mongoDb)
        {
            _identityUser = _collection;
            _tokenResponse = _collection1;
            _role = _collection2;
            _identityClaim = _collection3;
        }

        public CurrentIdentityUser Create(CurrentIdentityUser account)
        {
            try
            {
                var newAcc = new CurrentIdentityUser()
                {
                    //ID = _accounts.CountDocuments(new BsonDocument()) + 1,
                    UserName = account.UserName,
                    Email = account.Email,
                    Password = account.Password
                };
                _identityUser.InsertOne(newAcc);

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

        public List<CurrentIdentityUser> Get()
        {
            var res = _identityUser.Find(acc => true).ToList();
            return res;
        }

        public CurrentIdentityUser GetIdentityUserByName(string contextUsername)
        {
            //get your user model from db (by username - in my case its email)
            var acc = _identityUser.Find(e => e.UserName.Equals(contextUsername)).First();
            //Temp_AddClaims(acc);
            if (string.IsNullOrEmpty(acc.SecurityStamp))
            {
                acc.SecurityStamp = Guid.NewGuid().ToString();
                // TODO: at this time, I need to manually create Security Stamp for technical problem, will check again
                _identityUser.ReplaceOne(a => a.Id.Equals(acc.Id), acc);
            }
            return acc;
        }

        /// <summary>
        /// TODO: use for coding, programatical adding Claim to identity user
        /// </summary>
        /// <param name="acc"></param>
        private void Temp_AddClaims(CurrentIdentityUser acc)
        {
            if (acc.Claims.Count == 0)
            {
                // TODO: use when does not have claim
                //var newClaim = new MongoIdentityUserClaim()
                //{
                //    UserId = acc.Id.ToString(),
                //    ClaimType = JwtClaimTypes.Role,
                //    ClaimValue = "admin",
                //};
                //_identityClaim.InsertOne(newClaim);
                var dbClaim = _identityClaim.Find(e => e.Type.Equals(JwtClaimTypes.Role) && e.Value.Equals("admin")).First();
                if (!acc.Claims.Any(c => c.Issuer.Equals(dbClaim.UserId)))
                {
                    acc.Claims.Add(dbClaim);
                    _identityUser.ReplaceOne(a => a.Id.Equals(acc.Id), acc);
                }
            }
        }

        public CurrentIdentityUser GetIdentityUserByNameAndPassword(string contextUsername, string contextPassword)
        {
            //get your user model from db (by username - in my case its email)
            var acc = _identityUser.Find(e => e.UserName.Equals(contextUsername) && e.Password.Equals(contextPassword)).First();
            //Temp_AddClaims(acc);
            if (string.IsNullOrEmpty(acc.SecurityStamp))
            {
                acc.SecurityStamp = Guid.NewGuid().ToString();
                // TODO: at this time, I need to manually create Security Stamp for technical problem, will check again
                _identityUser.ReplaceOne(a => a.Id.Equals(acc.Id), acc);
            }

            return acc;
        }

        public CurrentIdentityUser GetById(string id)
        {
            var res = _identityUser.Find(s => s.Id.Equals(id)).First();
            return res;
        }

        public CurrentIdentityUser Update(CurrentIdentityUser newAcc)
        {
            var old = _identityUser.Find(s => s.Id.Equals(newAcc.Id)).First();

            // TODO:
            return old;
            //_accounts.UpdateOne(Builders<Account>.Filter.Eq(s => s.id, ObjectId.Parse(id)), newAcc);
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

        public CurrentIdentityUser CreateNewIdentityUser(string userName, string password)
        {
            throw new NotImplementedException();
        }

        public CurrentIdentityUser GetIdentityUser(CurrentIdentityUser identity)
        {
            throw new NotImplementedException();
        }
    }
}
