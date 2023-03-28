using IdentityModel;
using IdentityServer4;
using IdentityServer4.Models;
using IdentityServer4.Test;
using System.Collections.Generic;
using System.Security.Claims;
using WebApplication1.Controllers;

namespace WebApplication1
{
    public class Config
    {
        private static string reactproject1_testing_clientId = "reactproject1_testing";

        /// <summary>
        /// TODO: api scope for IS4 server
        /// </summary>
        public static IEnumerable<ApiScope> ApiScopes => new List<ApiScope>
            {
                new ApiScope()
                {
                    Name = "login",
                    DisplayName = "login",
                    UserClaims = { "role", "admin", "user", "login"}
                }
            };

        public static IEnumerable<IdentityResource> IdentityResources =>
            new List<IdentityResource>
            {
                new IdentityResources.OpenId()
                {
                    UserClaims = new [] { JwtClaimTypes.Subject, JwtClaimTypes.Id }
                },
                new IdentityResources.Profile(),
            };

        public static IEnumerable<ApiResource> ApiResources => new List<ApiResource>
            {
                // Add a resource for some set of APIs that we may be protecting
                // Note that the constructor will automatically create an allowed scope with
                // name and claims equal to the resource's name and claims. If the resource
                // has different scopes/levels of access, the scopes property can be set to
                // list specific scopes included in this resource, instead.
                new ApiResource("login", "Account controller", new List<string> { "role", "login"})
                {
                    Scopes =
                    {
                        "login",
                    }
                }
            };

        public static IEnumerable<Client> GetClients()
        {
            var cl = new List<Client>
            {
                new Client
                {
                    ClientId = reactproject1_testing_clientId,                    
                    // URL of client
                    ClientUri = "http://localhost:44371", 
                    //AllowedGrantTypes = GrantTypes.CodeAndClientCredentials,
                    AllowedGrantTypes = GrantTypes.ResourceOwnerPasswordAndClientCredentials,
                    // secret for authentication
                    ClientSecrets =
                    {
                        new Secret("511536EF-F270-4058-80CA-1C89C192F69A".Sha256())
                    },
                    // using this parameter, compare with authentication request from client(application) 
                    RedirectUris = { "http://localhost:44371/api/login" },
                    PostLogoutRedirectUris = { "http://localhost:44371/logout-callback-oidc" },
                    // scopes that client has access to
                    AllowedScopes =
                    {
                        IdentityServerConstants.StandardScopes.OpenId,
                        IdentityServerConstants.StandardScopes.Profile,
                        "createIdentityUser",
                        "updateIdentityUser",
                        "deleteIdentityUser"
                    },
                    // TODO: not clear how to use it
                    //AllowOfflineAccess = true,
                    // builds CORS policy for javascript clients
                    AllowedCorsOrigins = { "http://localhost:44371" }, 
                    // client is allowed to receive tokens via browser
                    AllowAccessTokensViaBrowser = true,
                    RequireConsent=false,
                }
            };

            return cl;
        }

        // TODO: need to custom claims of identityuser when using in resources server
        //     : separate identityserver with resources server mean, object of identity is different with two servers in logicaly way
        //     : (actually, these two still inside a physicaly server)
    }
}
