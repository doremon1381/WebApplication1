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
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;

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

            // database
            services.AddSingleton<IMongoClient>(s =>
                new MongoClient(config.GetValue<string>("FinalProjectDatabaseSetting:ConnectionString")));

            // authorization services
            services.AddAuthentication(options =>
            {
                // TODO: following 
                // https://identityserver4.readthedocs.io/en/latest/quickstarts/2_interactive_aspnetcore.html#adding-the-ui
                options.DefaultChallengeScheme = "oidc";
            }).AddGoogle(googleOptions =>
            {
                googleOptions.ClientId = config.GetValue<string>(AuthorizationThirdPartySetting.GetGoogleClientIdJsonConfigure());
                googleOptions.ClientSecret = config.GetValue<string>(AuthorizationThirdPartySetting.GetGoogleClientSecretJsonConfigure());
            }).AddCookie()
            .AddOpenIdConnect(OpenIdConnectDefaults.AuthenticationScheme, options =>
            {
                options.Authority = "http://localhost:44371";
                options.ClientId = "final-project-react";
                options.ClientSecret = "123456789";
                options.ResponseType = "code";
                //options.CallbackPath = "/signin-oidc";
                options.GetClaimsFromUserInfoEndpoint = true;
                options.SaveTokens = true;
                options.TokenValidationParameters = new TokenValidationParameters
                {
                    ValidateIssuerSigningKey = false,
                    SignatureValidator = delegate (string token, TokenValidationParameters validationParameters)
                    {
                        var jwt = new JwtSecurityToken(token);
                        return jwt;
                    },
                };
            });

            //services.AddAuthentication().AddOAuth(oauth )

            // TODO: obsolate
            //.AddjwtBearer();

            // TODO: I want to know that is this???
            // TODO: will add handle exception from global service class
            services.AddScoped<IAccountServices, AccountServices>();
            services.AddScoped<IAuthorizationServices, AuthorizingServices>();

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

            // TODO: Call UseAuthentication before any middleware that depends on users being authenticated.
            //     : https://learn.microsoft.com/en-us/aspnet/core/security/authentication/?view=aspnetcore-7.0
            app.UseAuthentication();
            app.UseAuthorization();

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllers();
            });
        }
    }
}
