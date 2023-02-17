using IdentityServer4;
using IdentityServer4.Models;
using System.Collections.Generic;
using WebApplication1.Controllers;

namespace WebApplication1
{
    public class Config
    {
        private static string reactproject1_testing_clientId = "reactproject1_testing";
        public static IEnumerable<ApiScope> GetApiScopes => new List<ApiScope>
            {
                new ApiScope("auth",nameof(AuthorizingController)),
            };

        public static IEnumerable<IdentityResource> IdentityResources =>
            new List<IdentityResource>
            {
                new IdentityResources.OpenId(),
                new IdentityResources.Profile(),
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
                    // no interactive user, use the clientid/secret for authentication
                    // TODO: testing for now
                    AllowedGrantTypes = GrantTypes.CodeAndClientCredentials,
                    // TODO: comment for test
                    //AllowedGrantTypes = GrantTypes.Hybrid,
                    // TODO: comment for test

                    // secret for authentication
                    ClientSecrets =
                    {
                        new Secret("511536EF-F270-4058-80CA-1C89C192F69A".Sha256())
                    },
                    RedirectUris = { "http://localhost:44371/login-oidc" },
                    PostLogoutRedirectUris = { "http://localhost:44371/logout-callback-oidc" },
                    // scopes that client has access to
                    AllowedScopes =
                    {
                        IdentityServerConstants.StandardScopes.OpenId,
                        IdentityServerConstants.StandardScopes.Profile,
                        "auth"
                    },
                    // TODO: not clear how to use it
                    //AllowOfflineAccess = true,
                    // builds CORS policy for javascript clients
                    AllowedCorsOrigins = { "http://localhost:44371" }, 
                    // client is allowed to receive tokens via browser
                    AllowAccessTokensViaBrowser = true
                }
            };
            return cl;
        }
    }
}
