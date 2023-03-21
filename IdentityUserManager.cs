using AspNetCore.Identity.Mongo.Model;
using IdentityModel;
using IdentityServer4;
using IdentityServer4.Extensions;
using IdentityServer4.Models;
using IdentityServer4.Services;
using IdentityServer4.Validation;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using MongoDB.Driver;
using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Threading.Tasks;
using WebApplication1.Models;
using WebApplication1.Services;

namespace WebApplication1
{
    public class ManuallyCreateProfileServices : DefaultProfileService
    {
        public ManuallyCreateProfileServices(ILogger<DefaultProfileService> logger) : base(logger)
        {
        }

        //public async Task GetProfileDataAsync(ProfileDataRequestContext context)
        //{
        //    // context.RequestedClaimTypes will contain the claims you requested when invoking the token endpoint
        //    var myClaims = await userManager.GetClaimsForUser(context.Subject, context.RequestedClaimTypes);
        //    context.IssuedClaims = myClaims;
        //}

        //public async Task IsActiveAsync(IsActiveContext context)
        //{
        //    context.IsActive = await userManager.IsActive(context.Subject);
        //}

        //
        // Summary:
        //     This method is called whenever claims about the user are requested (e.g. during
        //     token creation or via the userinfo endpoint)
        //
        // Parameters:
        //   context:
        //     The context.
        public override Task GetProfileDataAsync(ProfileDataRequestContext context)
        {
            context.LogProfileRequest(Logger);

            // TODO: manually add claims for /connect/userinfor response
            if (context.Caller.Equals(IdentityServerConstants.ProfileDataCallers.UserInfoEndpoint))
            {
                // Get data from Db
                var claims = new List<Claim>(context.Subject.Claims);
                context.IssuedClaims = claims;
            }
            else
            {
                context.IssuedClaims.AddRange(context.Subject.Claims);
            }

            context.LogIssuedClaims(Logger);
            return Task.CompletedTask;
        }

        //
        // Summary:
        //     This method gets called whenever identity server needs to determine if the user
        //     is valid or active (e.g. if the user's account has been deactivated since they
        //     logged in). (e.g. during token issuance or validation).
        //
        // Parameters:
        //   context:
        //     The context.
        public override Task IsActiveAsync(IsActiveContext context)
        {
            Logger.LogDebug("IsActive called from: {caller}", context.Caller);
            context.IsActive = true;
            return Task.CompletedTask;
        }
    }


    public class ManuallyCreateClaimsPrincipal : UserClaimsPrincipalFactory<Account, MongoRole>
    {
        private IMongoDatabase _dbContext;
        private UserManager<Account> _userManager;

        public ManuallyCreateClaimsPrincipal(IMongoDatabase dbContext, UserManager<Account> userManager, RoleManager<MongoRole> roleManager, IOptions<IdentityOptions> optionsAccessor)
            : base(userManager, roleManager, optionsAccessor)
        {
            _dbContext = dbContext;
            _userManager = userManager;
        }

        public override async Task<ClaimsPrincipal> CreateAsync(Account user)
        {
            var principal = await base.CreateAsync(user);

            //// Get user claims from DB using dbContext

            //// TODO: test Add claims
            //((ClaimsIdentity)principal.Identity).AddClaim(new Claim(JwtClaimTypes.Role, "user"));

            return principal;
        }
    }

    /// <summary>
    /// Login function
    /// </summary>
    public class ResourceOwnerPasswordValidator : IResourceOwnerPasswordValidator
    {
        //repository to get user from db
        private readonly ISigninContextServices  _signinContextServices;
        //private IAuthenticationServices _authenticationServices;
        private UserManager<Account> _userManager;

        public ResourceOwnerPasswordValidator(ISigninContextServices  accountServices, UserManager<Account> userManager)
        {
            _signinContextServices = accountServices; //DI
            _userManager = userManager;
        }

        // TODO:
        //this is used to validate your user account with provided grant at /connect/token
        public async Task ValidateAsync(ResourceOwnerPasswordValidationContext context)
        {
            try
            {
                Account user = GetAccountFromDb(context);
                if (user != null)
                {
                    // TODO:
                    //check if password match - remember to hash password if stored as hash in db
                    if (user.Password == context.Password)
                    {
                        // TODO:
                        //_authenticationServices.SignIn(user);

                        //set the result
                        context.Result = new GrantValidationResult(
                            subject: user.Id.ToString(),
                            authenticationMethod: "Resource Owner Password Flow",
                            claims: ManuallyCreateClaimsForUserIDentity(user));

                        return;
                    }

                    context.Result = new GrantValidationResult(TokenRequestErrors.InvalidGrant, "Incorrect password");
                    return;
                }
                context.Result = new GrantValidationResult(TokenRequestErrors.InvalidGrant, "User does not exist.");
                return;
            }
            catch (Exception)
            {
                context.Result = new GrantValidationResult(TokenRequestErrors.InvalidGrant, "Invalid username or password");
            }
        }

        // TODO:
        private Account GetAccountFromDb(ResourceOwnerPasswordValidationContext context)
        {
            //get your user model from db (by username - in my case its email)
            return _signinContextServices.GetByUserNameAndPassword(context.UserName, context.Password);
        }

        /// <summary>
        /// TODO: will check again
        /// build claims array from user data
        /// </summary>
        /// <param name="user"></param>
        /// <returns></returns>
        private List<Claim> ManuallyCreateClaimsForUserIDentity(Account user)
        {
            var claims = new List<Claim>
            {
                new Claim("user_id", user.Id.ToString() ?? ""),
                new Claim(JwtClaimTypes.Name, !string.IsNullOrEmpty(user.UserName) ? user.UserName : ""),
                new Claim(JwtClaimTypes.Email, user.Email  ?? ""),
                new Claim("Facebook", user.Facebook  ?? ""),
                new Claim(JwtClaimTypes.PhoneNumber, user.PhoneNumber  ?? ""),
        // TODO:
                //new Claim(JwtClaimTypes.Issuer, user),
                new Claim(JwtClaimTypes.Address, user.Address  ?? ""),
                new Claim(JwtClaimTypes.Role, user.Roles[0]),
                new Claim("api", user.Apis[0]),
            };

            for (int i = 0; i < user.Apis.Count; i++)
            {
                claims.Add(new Claim("api", user.Apis[i]));
            }

            return claims;
        }

        // TODO:
        //public enum UserRoles
        //{
        //    admin,
        //    user
        //}
    }
}
