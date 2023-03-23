using IdentityModel;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using MongoDB.Driver;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Security.Principal;
using System.IdentityModel.Tokens.Jwt;
using WebApplication1.Models.IdentityServer4;
using WebApplication1.Services.Base;
using WebApplication1.Models;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.IdentityModel.Tokens;
using System.Text;

namespace WebApplication1.Services
{
    public interface ISignInServices
    {
        CurrentIdentityUser GetIdentityByName(string contextUsername);
        CurrentIdentityUser GetIdentityByNameAndPassword(string contextUsername, string contextPassword);
        void SignIn(CurrentIdentityUser user);
        (string securityToken, bool isSuccess) SignIn(string accessToken);
    }

    /// <summary>
    /// Using for resource server, only have action to get identity, 
    /// not do anything with it in database (I assign this job for IS4)
    /// </summary>
    public class SignInServices : AbstractServices<CurrentIdentityUser>, ISignInServices
    {
        private IMongoCollection<CurrentIdentityUser> _currentIdentityUser;

        private SignInManager<CurrentIdentityUser> _signInManager;
        private UserManager<CurrentIdentityUser> _userManager;
        private RoleManager<CurrentIdentityRole> _roleManager;
        private HttpContext _httpContext;

        public SignInServices(IMongoDatabase mongoDb, HttpContextAccessor httpContextAccessor, 
            SignInManager<CurrentIdentityUser> signInManager, UserManager<CurrentIdentityUser> userManager, RoleManager<CurrentIdentityRole> roleManager) 
            : base(mongoDb)
        {
            _currentIdentityUser = _collection;

            _httpContext = httpContextAccessor.HttpContext;
            _roleManager = roleManager;
            _userManager = userManager;
            _signInManager = signInManager;
        }

        public CurrentIdentityUser GetIdentityByName(string contextUsername)
        {
            //get your user model from db (by username - in my case its email)
            var acc = _currentIdentityUser.Find(e => e.UserName.Equals(contextUsername)).First();
            if (string.IsNullOrEmpty(acc.SecurityStamp))
            {
                acc.SecurityStamp = Guid.NewGuid().ToString();
                // TODO: at this time, I need to manually create Security Stamp for technical problem, will check again
                _currentIdentityUser.ReplaceOne(a => a.Id.Equals(acc.Id), acc);
            }
            return acc;
        }

        public CurrentIdentityUser GetIdentityByNameAndPassword(string contextUsername, string contextPassword)
        {
            //get your user model from db (by username - in my case its email)
            var acc = _currentIdentityUser.Find(e => e.UserName.Equals(contextUsername) && e.Password.Equals(contextPassword)).First();
            if (string.IsNullOrEmpty(acc.SecurityStamp))
            {
                acc.SecurityStamp = Guid.NewGuid().ToString();
                // TODO: at this time, I need to manually create Security Stamp for technical problem, will check again
                _currentIdentityUser.ReplaceOne(a => a.Id.Equals(acc.Id), acc);
            }

            return acc;
        }

        /// <summary>
        /// Mean, create an IdentityUser, use SigninManager to excute function signin
        ///     , add claims to use for redirect request to enpoint, ex: you send to server a request with cookie(inside cookie has identity information or sth will be used to get IdentityUser object in server)
        ///                                                            : use to get IdentityUser in server, get claims from user and do sth before excute function inside services to resove request
        /// </summary>
        /// <param name="user"></param>
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
                var adminrole = GetAdminRole();
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


        /// <summary>
        /// TODO: still need to check again
        /// </summary>
        private void EnsureLogOut()
        {
            if (_httpContext.Request.Cookies.Count > 0)
            {
                // TODO: need to separate cookie use for authentication and login
                var siteCookies = _httpContext.Request.Cookies.Where(c => c.Key.Contains(".AspNetCore.") || c.Key.Contains("Microsoft.Authentication"));
                foreach (var cookie in siteCookies)
                {
                    // TODO: at this time, i dont know how to use this, so comment for now
                    _httpContext.Response.Cookies.Delete(cookie.Key);
                }
            }

            _httpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            _httpContext.Session.Clear();
        }



        public void AddAdminAccountToUserManager(CurrentIdentityUser tempUser)
        {
            // TODO: Get All comma-separated roles, temporary for now
            var roles = new string[] { "admin", "user" };
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
            var admin = _userManager.FindByEmailAsync(tempUser.Email).Result;
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

        public CurrentIdentityUser GetIdentityUser(CurrentIdentityUser account)
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

        private CurrentIdentityRole GetAdminRole()
        {
            CurrentIdentityRole role = new CurrentIdentityRole();
            try
            {
                var adminRole = _roleManager.FindByNameAsync("admin").Result;
                if (adminRole == null)
                {
                    var r = _roleManager.CreateAsync(adminRole).Result;
                    adminRole = _roleManager.FindByNameAsync("admin").Result;
                }

                role = adminRole;
                return role;
            }
            catch (Exception ex)
            {

                throw;
            }
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

        public (string securityToken, bool isSuccess) SignIn(string accessToken)
        {
            JwtSecurityToken token = new JwtSecurityToken(accessToken);

            Account acc = new Account();
            acc.GetFromAccessToken(token);

            //var str = token.Payload.ToString();
            //var newstr = JsonExtensions.SerializeToJson(token.Payload);

            var tk = GenerateJwtToken(acc.Subject);
            //var newstr = token.EncodedPayload;
            //token.Payload
            //throw new NotImplementedException();
            return (tk, true);
            // TODO: return cookie to client
        }


        /// <summary>
        /// Generate JWT Token after successful login.
        /// </summary>
        /// <param name="accountId"></param>
        /// <returns></returns>
        private string GenerateJwtToken(string userName)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes(AppSettingExtensions.JwtResourceServerKey);
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new[] { new Claim("id", userName) }),
                Expires = DateTime.UtcNow.AddHours(1),
                Issuer = AppSettingExtensions.JwtResourceServerIssuer,
                Audience = AppSettingExtensions.JwtResourceServerAuthority,
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
            };
            var token = tokenHandler.CreateToken(tokenDescriptor);
            return tokenHandler.WriteToken(token);
        }
    }
}
