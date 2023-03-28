using IdentityModel;
using IdentityServer4;
using IdentityServer4.Models;
using IdentityServer4.Services;
using IdentityServer4.Validation;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using MongoDB.Driver;
using Serilog;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using System.Windows.Input;
using WebApplication1.Common;
using WebApplication1.Models.IdentityServer4;
using WebApplication1.Services;

namespace WebApplication1
{
    public class ManuallyCreateProfileServices : DefaultProfileService
    {
        public ManuallyCreateProfileServices(Microsoft.Extensions.Logging.ILogger<DefaultProfileService> logger) : base(logger)
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
            // TODO:
            //context.LogProfileRequest(Logger);

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

            // TODO:
            //context.LogIssuedClaims(Logger);
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
            // TODO:
            //Logger.LogDebug("IsActive called from: {caller}", context.Caller);
            context.IsActive = true;
            return Task.CompletedTask;
        }
    }

    public class ManuallyCreateClaimsPrincipal : UserClaimsPrincipalFactory<CurrentIdentityUser, CurrentIdentityRole>
    {
        private IMongoDatabase _dbContext;
        private UserManager<CurrentIdentityUser> _userManager;

        public ManuallyCreateClaimsPrincipal(IMongoDatabase dbContext, UserManager<CurrentIdentityUser> userManager, RoleManager<CurrentIdentityRole> roleManager, IOptions<IdentityOptions> optionsAccessor)
            : base(userManager, roleManager, optionsAccessor)
        {
            _dbContext = dbContext;
            _userManager = userManager;
        }

        public override async Task<ClaimsPrincipal> CreateAsync(CurrentIdentityUser user)
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
        private IdentityServerUserManager _identityServerUserManager;

        public ResourceOwnerPasswordValidator(IdentityServerUserManager identityServerUserManager)
        {
            _identityServerUserManager = identityServerUserManager;
        }

        // TODO:
        //this is used to validate your user account with provided grant at /connect/token
        public async Task ValidateAsync(ResourceOwnerPasswordValidationContext context)
        {
            try
            {
                CurrentIdentityUser user = _identityServerUserManager.GetIdentityUserCommand.Excute((userName: context.UserName, password: context.Password));
                if (user != null)
                {
                    //set the result
                    context.Result = new GrantValidationResult(
                        subject: user.Id.ToString(),
                        authenticationMethod: "Resource Owner Password Flow");
                    // TODO: comment for now
                    //claims: ManuallyCreateClaimsForUserIDentity(user));
                }
                else
                {
                    context.Result = new GrantValidationResult(TokenRequestErrors.InvalidGrant, "User does not exist.");
                    return;
                }
            }
            catch (Exception)
            {
                context.Result = new GrantValidationResult(TokenRequestErrors.InvalidGrant, "Invalid username or password");
            }
        }
    }

    public class IdentityServerUserManager
    {
        private IIdentityUserServices _identityUserServices;
        private ActionWithLog<(string userName, string password), CurrentIdentityUser> _GetIdentityUser;
        private List<CurrentIdentityUser> _users = new List<CurrentIdentityUser>();

        public IdentityServerUserManager(IIdentityUserServices identityUserServices, ILogger logger)
        {
            _identityUserServices = identityUserServices;

            _GetIdentityUser = new ActionWithLog<(string userName, string password), CurrentIdentityUser>((p) => { return GetIdentityUser(p.userName, p.password); }, "GetIdentityUser", logger);
        }

        public ActionWithLog<(string userName, string password), CurrentIdentityUser> GetIdentityUserCommand
        {
            get => _GetIdentityUser;
            private set
            {
                _GetIdentityUser = value;
            }
        }

        private CurrentIdentityUser GetIdentityUser(string userName, string password)
        {
            // if list of users in is4 already has an instance has same userName.
            if (_users.Any(u => u.UserName.Equals(userName)))
            {
                // then check currently instance's password
                using (var currentUser = _users.Find(u => u.UserName.Equals(userName) && u.Password.Equals(password)))
                {
                    // if already has an instance match two conditions, return this
                    if (currentUser != null)
                    {
                        return currentUser;
                    }
                }
            }
            // if user with userName is not inside is4 list of users, check database
            else
            {
                using (var currentUser = _identityUserServices.GetIdentityUserByName(userName))
                {
                    if (currentUser == null
                        || !currentUser.Password.Equals(password))
                        return null;

                    // if user's identity information is equal with current identity model (userName and password), return this
                    return currentUser;
                }
            }

            return null;
        }
    }
}
