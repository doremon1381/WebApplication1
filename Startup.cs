using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using MongoDB.Driver;
using System.IO;
using WebApplication1.Services;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using IdentityServer4;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;

namespace WebApplication1
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            #region acceptable
            var builder = new ConfigurationBuilder()
                .SetBasePath(Directory.GetCurrentDirectory())
                .AddJsonFile("appsettings.json", optional: false, reloadOnChange: true)
                .AddEnvironmentVariables();
            IConfiguration config = builder.Build();

            // settings
            services.Configure<FinalProjectDatabaseSetting>(config.GetSection(nameof(FinalProjectDatabaseSetting)));
            services.AddSingleton<IFinalProjectDatabaseSetting>(sp =>
                sp.GetRequiredService<IOptions<FinalProjectDatabaseSetting>>().Value);
            services.Configure<AuthorizationThirdPartySetting>(config.GetSection(nameof(AuthorizationThirdPartySetting)));
            services.AddSingleton<IAuthorizationThirdPartySetting>(sp =>
                sp.GetRequiredService<IOptions<AuthorizationThirdPartySetting>>().Value);
            services.Configure<OpenIDConnectionClient>(config.GetSection(nameof(OpenIDConnectionClient)));
            services.AddSingleton<OpenIDConnectionClient>(sp =>
                sp.GetRequiredService<IOptions<OpenIDConnectionClient>>().Value);

            // database
            services.AddSingleton<IMongoClient>(s =>
                new MongoClient(config.GetValue<string>(AppSettingExtensions.DatabaseConnectionAddress)));
            #endregion acceptable

            #region modifying
            // REMARKABLE: can not use cause the sequence of execution of code which this function
            //           : .AddInMemoryApiResources()
            //           : inside, from running it to operation of Identityserver
            //           : somehow just dont do what I want
            //           : still dont know difference between "AddInMemoryApiScopes" and "AddInMemoryApiResources" in how it work?
            services.AddIdentityServer()
                    .AddInMemoryApiScopes(Config.GetApiScopes)
                    .AddInMemoryIdentityResources(Config.IdentityResources)
                    //.AddInMemoryApiResources(Config.GetApiResources()) - OLD :v
                    .AddInMemoryClients(Config.GetClients())
                    .AddDeveloperSigningCredential(); // TODO: for test, will add Identity Credential later (still dont know how to add an "Identity credential"), getting from database or sth else?

            // authorization services
            services.AddAuthentication(options =>
            {
                //options.DefaultAuthenticateScheme = "oidc";
                //options.DefaultSignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                //options.DefaultChallengeScheme = CookieAuthenticationDefaults.AuthenticationScheme;

                // TODO: following 
                //// https://identityserver4.readthedocs.io/en/latest/quickstarts/2_interactive_aspnetcore.html#adding-the-ui
                //options.DefaultChallengeScheme = "oidc";
                //options.DefaultScheme = "Cookies";

                // follow: https://stackoverflow.com/questions/59638965/how-to-add-openidconnect-via-identityserver4-to-asp-net-core-serverside-blazor-w
                options.DefaultAuthenticateScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                options.DefaultSignInScheme =CookieAuthenticationDefaults.AuthenticationScheme;
                options.DefaultChallengeScheme =OpenIdConnectDefaults.AuthenticationScheme;
                //}).AddCookie("Cookies") // TODO: the "Cookies" as parameter inside "AddCookie" funcion is "authenticationScheme"
            }).AddCookie()
            .AddOpenIdConnect("oidc", options =>
            {
                // TODO: using "options.RequireHttpsMetadata = false" for debug, 
                //     : will learn to use https://github.com/aspnet/Security/blob/release/2.1/src/Microsoft.AspNetCore.Authentication.JwtBearer/JwtBearerOptions.cs#L23
                options.RequireHttpsMetadata = false;

                options.Authority = config.GetValue<string>(AppSettingExtensions.OpenIDConnectConfigAddress(OpenIDConnectionConfig.AUTHORITY));
                options.ClientId = config.GetValue<string>(AppSettingExtensions.OpenIDConnectConfigAddress(OpenIDConnectionConfig.CLIENTID));
                options.ClientSecret = config.GetValue<string>(AppSettingExtensions.OpenIDConnectConfigAddress(OpenIDConnectionConfig.CLIENTSECRET));
                //options.ResponseType = config.GetValue<string>(AppSettingExtensions.OpenIDConnectString(OpenIDConnectionConfig.RESPONSETYPE));
                options.ResponseType = OpenIdConnectResponseType.Code;

                options.SaveTokens = true;
                options.GetClaimsFromUserInfoEndpoint = true;
                options.Scope.Add("openid");
                options.Scope.Add("profile");
                options.Scope.Add("auth");

                //// TODO: not sure how to use it
                //// using with non standard claim, but it is not my situation (using only standard claim)
                //// https://identityserver4.readthedocs.io/en/latest/quickstarts/2_interactive_aspnetcore.html
                //// options.ClaimActions.MapJsonKey("website", "website");
                //options.TokenValidationParameters = new TokenValidationParameters
                //{
                //    ValidateIssuerSigningKey = false,
                //    SignatureValidator = delegate (string token, TokenValidationParameters validationParameters)
                //    {
                //        var jwt = new JwtSecurityToken(token);
                //        return jwt;
                //    },
                //};
            }).AddGoogle(googleOptions =>
            {
                // TODO: When using external authentication with ASP.NET Core Identity, the SignInScheme must be set to "Identity.External" instead of IdentityServerConstants.ExternalCookieAuthenticationScheme.
                // https://identityserver4.readthedocs.io/en/aspnetcore1/quickstarts/4_external_authentication.html
                googleOptions.SignInScheme = IdentityServerConstants.ExternalCookieAuthenticationScheme;

                googleOptions.ClientId = config.GetValue<string>(AppSettingExtensions.GoogleConfigAddress(OAuthConfig.CLIENTID));
                googleOptions.ClientSecret = config.GetValue<string>(AppSettingExtensions.GoogleConfigAddress(OAuthConfig.CLIENTSECRET));
            });

            //// IDEAL: adds an authorization policy to make sure the token is for scope 'api1'
            //services.AddAuthorization(options =>
            //{
            //    options.AddPolicy("ApiScope", policy =>
            //    {
            //        policy.RequireAuthenticatedUser();
            //        policy.RequireClaim("scope", "auth");
            //    });
            //});

            // TODO: I want to know that is this???
            // TODO: will add handle exception from global service class
            services.AddScoped<IAccountServices, AccountServices>();
            services.AddScoped<IAuthorizationServices, AuthorizingServices>();
            #endregion modifying

            services.AddControllers();
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }

            app.UseHttpsRedirection();

            app.UseRouting();


            // WARNING: UseIdentityServer includes a call to UseAuthentication, so itfs not necessary to have both.
            // https://identityserver4.readthedocs.io/en/latest/topics/startup.html
            // TODO: Call UseAuthentication before any middleware that depends on users being authenticated.
            //     : https://learn.microsoft.com/en-us/aspnet/core/security/authentication/?view=aspnetcore-7.0
            app.UseIdentityServer();
            app.UseAuthorization();

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllers();
            });
        }
    }
}
