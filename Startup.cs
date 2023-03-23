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
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using WebApplication1.Models;
using Microsoft.AspNetCore.Identity;
using System;
using Serilog;
using Serilog.Events;
using WebApplication1.Common;
using Microsoft.AspNetCore.Http;
using AspNetCore.Identity.MongoDbCore.Infrastructure;
using AspNetCore.Identity.MongoDbCore.Extensions;
using AspNetCore.Identity.MongoDbCore.Models;
using MongoDB.Bson;
using MongoDbGenericRepository;
using WebApplication1.Models.IdentityServer4;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.DataProtection.KeyManagement;
using Microsoft.IdentityModel.Tokens;
using System.Text;

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

            AppSettingExtensions.GetFromAppSettings(config);

            // TODO: will do sth
            //     :https://stackoverflow.com/questions/67255591/using-asp-net-core-identity-with-mongodb
            // database
            var mongoDb = new MongoDbContext(AppSettingExtensions.ConnectionString, AppSettingExtensions.DatabaseName);
            // TODO: will do sth
            services.AddScoped<IMongoDatabase>(sp => mongoDb.Database);

            services.AddIdentity<CurrentIdentityUser, CurrentIdentityRole>()
                .AddMongoDbStores<IMongoDbContext>(mongoDb)
                .AddDefaultTokenProviders();

            var mongoDbIdentityConfiguration = new MongoDbIdentityConfiguration
            {
                MongoDbSettings = new MongoDbSettings
                {
                    ConnectionString = AppSettingExtensions.ConnectionString,
                    DatabaseName = AppSettingExtensions.DatabaseName
                },
                IdentityOptionsAction = options =>
                {
                    options.Password.RequireDigit = false;
                    //// TODO: will do sth
                    //options.Password.RequiredLength = 8;
                    options.Password.RequireNonAlphanumeric = false;
                    options.Password.RequireUppercase = false;
                    options.Password.RequireLowercase = false;

                    // Lockout settings
                    options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(30);
                    //// TODO: will do sth
                    //options.Lockout.MaxFailedAccessAttempts = 10;

                    // ApplicationUser settings
                    options.User.RequireUniqueEmail = true;
                    options.User.AllowedUserNameCharacters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789@.-_";
                }
            };
            services.ConfigureMongoDbIdentity<CurrentIdentityUser, CurrentIdentityRole, ObjectId>(mongoDbIdentityConfiguration)
                    .AddDefaultTokenProviders()
                    .AddClaimsPrincipalFactory<ManuallyCreateClaimsPrincipal>();
            #endregion acceptable

            #region modifying
            // REMARK: can not use cause the sequence of execution of programaticaly atoms (blocks of code) which this function
            //           : .AddInMemoryApiResources()
            //           : inside, from running it to operation of Identityserver
            //           : somehow just dont do what I want
            //           : still dont know difference between "AddInMemoryApiScopes" and "AddInMemoryApiResources" in how it work?
            services.AddIdentityServer()
                    //// TODO: comment for test
                    //.AddInMemoryApiScopes(Config.ApiScopes)
                    .AddInMemoryIdentityResources(Config.IdentityResources)
                    .AddInMemoryApiResources(Config.ApiResources)
                    //- it's replaced with ApiScopes, but when using this function, I just don't know :v
                    .AddInMemoryClients(Config.GetClients())
                    //// TODO: comment for test
                    //.AddAspNetIdentity<Account>()
                    .AddProfileService<ManuallyCreateProfileServices>()
                    .AddResourceOwnerValidator<ResourceOwnerPasswordValidator>()
                    //.AddSigningCredential(new X509Certificate2(Path.Combine(".", "certs", "webApplication1.pfx"), AppSettingExtensions.SignInCredentialCryptoServicesPassword))
                    .AddDeveloperSigningCredential();
            //.AddDeveloperSigningCredential(); // TODO: for test, will add Identity Credential later (still dont know how to add an "Identity credential"), getting from database or sth else?

            // authorization services
            services.AddAuthentication(options =>
            {
                // TODO: following 
                //// https://identityserver4.readthedocs.io/en/latest/quickstarts/2_interactive_aspnetcore.html#adding-the-ui
                //options.DefaultChallengeScheme = "oidc";
                //options.DefaultScheme = "Cookies";

                // follow: https://stackoverflow.com/questions/59638965/how-to-add-openidconnect-via-identityserver4-to-asp-net-core-serverside-blazor-w
                options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
                // TODO: comment for now
                //options.DefaultSignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                options.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
                //}).AddCookie("Cookies") // TODO: the "Cookies" as parameter inside "AddCookie" funcion is "authenticationScheme"
            })
            // TODO: will check again
            //.AddCookie(cookieAuthenticationOptions => 
            //{
            //    cookieAuthenticationOptions.Events.OnValidatePrincipal = (cookie) => SecurityStampValidator.ValidatePrincipalAsync(cookie);
            //})
            .AddCookie((options) => 
            {
                options.Cookie.Name = "webApplication1"; 
            })
            .AddOpenIdConnect("oidc", options =>
            {
                // TODO: using "options.RequireHttpsMetadata = false" for debug, 
                //     : will learn to use https://github.com/aspnet/Security/blob/release/2.1/src/Microsoft.AspNetCore.Authentication.JwtBearer/JwtBearerOptions.cs#L23
                options.RequireHttpsMetadata = false;

                options.Authority = AppSettingExtensions.Authority;
                options.ClientId = AppSettingExtensions.ClientId;
                options.ClientSecret = AppSettingExtensions.ClientSecret;
                // TODO: try to return id_token, knowing that currently using ResourceOwnerPassword flow
                options.ResponseType = OpenIdConnectResponseType.CodeIdToken;

                options.SaveTokens = true;
                options.GetClaimsFromUserInfoEndpoint = true;
                options.Scope.Add("openid");
                options.Scope.Add("profile");
                options.Scope.Add("createIdentityUser");
                options.Scope.Add("updateIdentityUser");
                options.Scope.Add("deleteIdentityUser");

                //// TODO: not sure how to use it
                //// https://learn.microsoft.com/en-us/aspnet/core/security/authentication/claims?view=aspnetcore-5.0
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
            })
            .AddJwtBearer(JwtBearerDefaults.AuthenticationScheme, (options) => 
            {
                string issuer = AppSettingExtensions.Authority;

                options.TokenValidationParameters = new TokenValidationParameters
                {
                    ValidateIssuer = true,
                    ValidateAudience = true,
                    ValidateLifetime = false,
                    ValidateIssuerSigningKey = true,
                    ValidIssuer = AppSettingExtensions.JwtResourceServerIssuer,
                    ValidAudience = AppSettingExtensions.JwtResourceServerAuthority,
                    IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(AppSettingExtensions.JwtResourceServerKey)) //Configuration["JwtToken:SecretKey"]
                };

                options.Events = new JwtBearerEvents
                {
                    OnAuthenticationFailed = context =>
                    {
                        if (context.Exception.GetType() == typeof(SecurityTokenExpiredException))
                        {
                            context.Response.Headers.Add("Token-Expired", "true");
                        }
                        return System.Threading.Tasks.Task.CompletedTask;
                    }
                };
            })
            // TODO: for more info https://stackoverflow.com/questions/52765570/accessing-protected-api-on-identityserver4-with-bearer-token
            //.AddJwtBearer(jwtOptions => 
            //{
            //    jwtOptions.Authority = AppSettingExtensions.Authority;
            //    // TODO: using "options.RequireHttpsMetadata = false" for debug, 
            //    //     : will learn to use https://github.com/aspnet/Security/blob/release/2.1/src/Microsoft.AspNetCore.Authentication.JwtBearer/JwtBearerOptions.cs#L23
            //    jwtOptions.RequireHttpsMetadata = false;
            //    jwtOptions.Audience = "login";
            //})
            ;
            //.AddGoogle(googleOptions =>
            //{
            //    // TODO: When using external authentication with ASP.NET Core Identity, the SignInScheme must be set to "Identity.External" instead of IdentityServerConstants.ExternalCookieAuthenticationScheme.
            //    // https://identityserver4.readthedocs.io/en/aspnetcore1/quickstarts/4_external_authentication.html
            //    googleOptions.SignInScheme = IdentityServerConstants.ExternalCookieAuthenticationScheme;

            //    googleOptions.ClientId = config.GetValue<string>(AppSettingExtensions.GoogleConfigAddress(OAuthConfig.CLIENTID));
            //    googleOptions.ClientSecret = config.GetValue<string>(AppSettingExtensions.GoogleConfigAAddress(OAuthConfig.CLIENTSECRET));
            //});

            //// IDEAL: adds an authorization policy to make sure the token is for scope 'api1'
            //services.AddAuthorization(options =>
            //{
            //    options.AddPolicy("login", policy =>
            //    {
            //        //policy.RequireAuthenticatedUser();
            //        policy.RequireClaim("scope", "Authorizing.login");
            //    });
            //});
            services.AddLogging(builder =>
            {
                var logger = new LoggerConfiguration()
                              .MinimumLevel.Information()
                              .WriteTo.File(path: "\\Logs", restrictedToMinimumLevel: LogEventLevel.Information, outputTemplate: "[{Timestamp:HH:mm:ss} {Level:u3}] {Message:lj}{NewLine}{Exception}",
                              fileSizeLimitBytes: 1000000, rollOnFileSizeLimit: true, retainedFileCountLimit: 365, retainedFileTimeLimit: new TimeSpan(365, 0, 0, 0))
                              .CreateLogger();
                builder.AddSerilog(logger);
            })
            //this is important
            .AddSingleton<Serilog.ILogger>(sp =>
            {
                return new LoggerConfiguration()
                    .MinimumLevel.Debug()
                    .CreateLogger();
            });

            // TODO: I want to know that is this???
            // TODO: will add handle exception from global service class
            //services.AddScoped<IAccountServices, AccountServices>();
            services.AddScoped<IAuthenticationServices, AuthenticationServices>();
            services.AddScoped<ISignInServices, SignInServices>();
            services.AddScoped<ITokenResponseServices, TokenResponseServices>();
            #region obsolate
            // TODO: for more info https://stackoverflow.com/questions/60515534/asp-net-core-how-to-get-usermanager-working-in-controller
            //services.AddScoped<UserManager<Account>>();
            //services.AddScoped<SignInManager<Account>>();
            #endregion
            services.AddScoped<HttpContextAccessor>();
            services.AddScoped<ActionController>();
            services.AddSession((options) => 
            {
                options.IdleTimeout = TimeSpan.FromMinutes(30);//We set Time here 
                options.Cookie.HttpOnly = true;
                options.Cookie.IsEssential = true;
            });
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

            //TODO 
            app.UseSession();

            // WARNING: UseIdentityServer includes a call to UseAuthentication, so itfs not necessary to have both.
            // https://identityserver4.readthedocs.io/en/latest/topics/startup.html
            // INFO: Call UseAuthentication before any middleware that depends on users being authenticated.
            //     : https://learn.microsoft.com/en-us/aspnet/core/security/authentication/?view=aspnetcore-7.0
            app.UseIdentityServer();

            // WARNING: still need
            // https://learn.microsoft.com/en-us/aspnet/core/security/authentication/identity-api-authorization?view=aspnetcore-5.0
            // The authentication middleware that is responsible for validating the request credentials and setting the user on the request context:
            app.UseAuthentication();
            app.UseAuthorization();
            //// TODO: will check again
            //InitializeRoles(roleManager);
            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllers();
            });
        }
    }
}
