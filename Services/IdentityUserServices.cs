using Microsoft.AspNetCore.Authentication.Cookies;
using MongoDB.Driver;
using System.Collections.Generic;
using System.Security.Claims;
using System;
using WebApplication1.Models.IdentityServer4;
using WebApplication1.Services.Base;
using IdentityModel;
using System.Linq;

namespace WebApplication1.Services
{
    public interface IIdentityUserServices : IServices<CurrentIdentityUser>
    {
        CurrentIdentityUser GetIdentityUserByName(string username);
        CurrentIdentityUser GetIdentityUserByNameAndPassword(string contextUsername, string contextPassword);
        CurrentIdentityUser CreateNewIdentityUser(string userName, string password);
        CurrentIdentityUser GetIdentityUser(CurrentIdentityUser identity);
        CurrentIdentityUser UpdateUserPassword(CurrentIdentityUser user, string password);
    }

    public class IdentityUserServices : AbstractServices<CurrentIdentityUser, CurrentIdentityRole, CurrentUserClaim>, IIdentityUserServices
    {
        private IMongoCollection<CurrentIdentityUser> _identityUser;
        private IMongoCollection<CurrentIdentityRole> _role;
        private IMongoCollection<CurrentUserClaim> _identityClaim;

        public IdentityUserServices(IMongoDatabase database) : base(database)
        {
            _identityUser = _collection;
            _role = _collection1;
            _identityClaim = _collection2;
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

        public CurrentIdentityUser GetIdentityUserByName(string username)
        {
            //get your user model from db (by username - in my case its email)
            var acc = _identityUser.Find(e => e.UserName.Equals(username)).First();
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

        public CurrentIdentityUser CreateNewIdentityUser(string userName, string password)
        {
            throw new NotImplementedException();
        }

        public CurrentIdentityUser GetById(string id)
        {
            throw new NotImplementedException();
        }

        public CurrentIdentityUser GetIdentityUser(CurrentIdentityUser identity)
        {
            throw new NotImplementedException();
        }

        public CurrentIdentityUser Update(CurrentIdentityUser document)
        {
            throw new NotImplementedException();
        }

        /// <summary>
        /// use for updating current user of identity server with different password
        /// </summary>
        /// <param name="userName"></param>
        /// <param name="password"></param>
        /// <returns></returns>
        /// <exception cref="NotImplementedException"></exception>
        public CurrentIdentityUser UpdateUserPassword(CurrentIdentityUser user, string password)
        {
            user.Password = password;

            _identityUser.ReplaceOne(u => u.Id.Equals(user.Id), user);
            var newUser = GetIdentityUserByNameAndPassword(user.UserName, user.Password);
            return newUser;
        }
    }
}
