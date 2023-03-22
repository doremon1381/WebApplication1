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
using WebApplication1.Models;
using AspNetCore.Identity.MongoDbCore.Models;

namespace WebApplication1.Services
{
    public interface ISigninContextServices : IServices<CurrentIdentityUser>
    {
        CurrentIdentityUser GetByUserName(string contextUsername);
        CurrentIdentityUser GetByUserNameAndPassword(string contextUsername, string contextPassword);
        TokenResponse Create(Google.Apis.Auth.OAuth2.Responses.TokenResponse gToken);
        void SignIn(CurrentIdentityUser user);
        CurrentIdentityUser GetUser(CurrentIdentityUser account);
    }

    /// <summary>
    /// Intent to use for user login, without google or facebook
    /// </summary>
    public class SigninContextServices : AbstractServices<CurrentIdentityUser, TokenResponse, CurrentIdentityRole, CurrentUserClaim>, ISigninContextServices
    {
        private IMongoCollection<CurrentIdentityUser> _account;
        private IMongoCollection<TokenResponse> _tokenResponse;
        private IMongoCollection<CurrentIdentityRole> _role;
        private IMongoCollection<CurrentUserClaim> _identityClaim;

        private SignInManager<CurrentIdentityUser> _signInManager;
        private UserManager<CurrentIdentityUser> _userManager;
        private RoleManager<CurrentIdentityRole> _roleManager;
        private HttpContext _httpContext;

        public SigninContextServices(IMongoDatabase mongoDb, HttpContextAccessor httpContextAccessor, 
            SignInManager<CurrentIdentityUser> signInManager, UserManager<CurrentIdentityUser> userManager, RoleManager<CurrentIdentityRole> roleManager) 
            : base(mongoDb)
        {
            _account = _collection;
            _tokenResponse = _collection1;
            _role = _collection2;
            _identityClaim = _collection3;

            _signInManager = signInManager;
            _userManager = userManager;
            _httpContext = httpContextAccessor.HttpContext;
            _roleManager = roleManager;
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

        public List<CurrentIdentityUser> Get()
        {
            var res = _account.Find(acc => true).ToList();
            return res;
        }

        public CurrentIdentityUser GetByUserName(string contextUsername)
        {
            //get your user model from db (by username - in my case its email)
            var acc = _account.Find(e => e.UserName.Equals(contextUsername)).First();
            Temp_AddClaims(acc);
            if (string.IsNullOrEmpty(acc.SecurityStamp))
            {
                acc.SecurityStamp = Guid.NewGuid().ToString();
                // TODO: at this time, I need to manually create Security Stamp for technical problem, will check again
                _account.ReplaceOne(a => a.Id.Equals(acc.Id), acc);
            }
            return acc;
        }

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
                    _account.ReplaceOne(a => a.Id.Equals(acc.Id), acc);
                }
            }
        }

        public CurrentIdentityUser GetByUserNameAndPassword(string contextUsername, string contextPassword)
        {
            //get your user model from db (by username - in my case its email)
            var acc = _account.Find(e => e.UserName.Equals(contextUsername) && e.Password.Equals(contextPassword)).First();
            Temp_AddClaims(acc);
            if (string.IsNullOrEmpty(acc.SecurityStamp))
            {
                acc.SecurityStamp = Guid.NewGuid().ToString();
                // TODO: at this time, I need to manually create Security Stamp for technical problem, will check again
                _account.ReplaceOne(a => a.Id.Equals(acc.Id), acc);
            }

            return acc;
        }

        public CurrentIdentityUser GetById(string id)
        {
            var res = _account.Find(s => s.Id.Equals(id)).First();
            return res;
        }

        public CurrentIdentityUser Update(CurrentIdentityUser newAcc)
        {
            var old = _account.Find(s => s.Id.Equals(newAcc.Id)).First();

            // TODO:
            return old;
            //_accounts.UpdateOne(Builders<Account>.Filter.Eq(s => s.id, ObjectId.Parse(id)), newAcc);
        }

        public void SignIn(CurrentIdentityUser user)
        {
            try
            {
                //// signin, login, authen or anything like these
                //var createUser = _userManager.CreateAsync(user).Result;

                // TODO: not done
                //if (_role.EstimatedDocumentCount() == 0)
                //{
                //    _role.InsertOne(new MongoRole("admin"));
                //}
                EnsureLogOut();
                var adminrole = GetRole();
                if (user.Roles.Contains(adminrole.Id))
                {
                    AddAdminAccountToUserManager(user);
                }
                //var currentUser = _userManager.FindByNameAsync($"{user.Name}").Result;

                //user.Roles.Add(admin.Id.ToString());
                // TODO: dont use asynchonous in this programaticaly function
                //var signinAsync = await _signInManager.SignInWithClaimsAsync(user, isPersistent: true, );
                //var s1 = _signInManager.PasswordSignInAsync(user.UserName, user.Password, isPersistent: true, false);
                var signin = _signInManager.SignInWithClaimsAsync(user, isPersistent: true, ManuallyCreateClaimsForUserIDentity(user, adminrole.Name));
                var createUserClaim = _signInManager.CreateUserPrincipalAsync(user).Result;
                bool isSignIn = _signInManager.IsSignedIn(createUserClaim);
                if (isSignIn)
                {
                    var user1 = _userManager.FindByNameAsync(user.UserName).Result;
                    var userId = user.Id;
                }
            }
            catch (Exception)
            {
                // TODO: write code for log action later
                //Log.Logger.BindMessageTemplate
                throw;
            }
        }

        public void AddAdminAccountToUserManager(CurrentIdentityUser tempUser)
        {
            // TODO: Get All comma-separated roles, temporary for now
            var roles = new string[]{"admin", "user" };
            // Create roles if they don’t exist
            foreach (var role in roles)
            {
                if (!_roleManager.RoleExistsAsync(role).Result)
                {
                    CurrentIdentityRole storageRole = new CurrentIdentityRole
                    {
                        Name = role
                    };
                    IdentityResult roleResult = _roleManager.CreateAsync(storageRole).Result;
                }
            }
            // Create admin if he doesn’t exist
            var admin =  _userManager.FindByEmailAsync(tempUser.Email).Result;
            if (admin == null)
            {
                CurrentIdentityUser user = tempUser;
                IdentityResult result = _userManager.CreateAsync(user, user.Password).Result;
                _userManager.AddClaimAsync(user, new Claim(JwtClaimTypes.Email, user.Email));
                _userManager.AddClaimAsync(user, new Claim("IsActive", "True"));
                // Add Admin to Admin roles
                if (result.Succeeded)
                {
                    //var identity = _userManager.AddToRoleAsync(user, "Admin").Result;
                }
                else
                {
                    if (result.Errors.Any())
                    {

                    }
                }
            }
        }

        /// <summary>
        /// TODO: still need to check again
        /// </summary>
        private void EnsureLogOut()
        {
            if (_httpContext.Request.Cookies.Count > 0)
            {
                var siteCookies = _httpContext.Request.Cookies.Where(c => c.Key.Contains(".AspNetCore.") || c.Key.Contains("Microsoft.Authentication"));
                foreach (var cookie in siteCookies)
                {
                    _httpContext.Response.Cookies.Delete(cookie.Key);
                }
            }

            _httpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            _httpContext.Session.Clear();
        }

        public CurrentIdentityUser GetUser(CurrentIdentityUser account)
        {
            try
            {
                //var cl1 = _signInManager.ClaimsFactory
                //var cl = _userManager.get
                //var srr  = _signInManager.

                var acc = _userManager.Users.First();

                return acc;
            }
            catch (Exception)
            {
                return null;
            }
        }

        private async void LogError()
        {

        }

        private CurrentIdentityRole GetRole()
        {
            CurrentIdentityRole role = new CurrentIdentityRole();
            try
            {
                var current = _role.Find(r => r.ConcurrencyStamp.Equals("eca8a227-567c-4baf-8d8f-05f52819c50f")).First();
                if (_roleManager.FindByNameAsync("admin").Result == null)
                {
                    var r = _roleManager.CreateAsync(current).Result;
                    current = _roleManager.FindByNameAsync("admin").Result;
                }

                role = current;
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
        private List<Claim> ManuallyCreateClaimsForUserIDentity(CurrentIdentityUser user, string roleNameForCurrentUser)
        {
            var claims = new List<Claim>
            {
                new Claim("user_id", user.Id.ToString() ?? ""),
                new Claim(JwtClaimTypes.Name, !string.IsNullOrEmpty(user.UserName) ? user.UserName : ""),
                new Claim(JwtClaimTypes.Email, user.Email  ?? ""),
                new Claim("Facebook", user.Facebook  ?? ""),
                new Claim(JwtClaimTypes.PhoneNumber, user.PhoneNumber  ?? ""),
                //new Claim(JwtClaimTypes.Issuer, user),
                new Claim(JwtClaimTypes.Address, user.Address  ?? ""),
                new Claim(JwtClaimTypes.Role, roleNameForCurrentUser),
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
