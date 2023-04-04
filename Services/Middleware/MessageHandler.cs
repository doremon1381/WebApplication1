using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Web.Administration;
using System;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace WebApplication1.Services.Middleware
{
    /// <summary>
    /// implement Basic authentication
    /// </summary>
    public class MessageHandler
    {
        private readonly RequestDelegate _request;
        public MessageHandler(RequestDelegate next) =>
        _request = next;

        public Task Invoke(HttpContext httpContext)
        {
            //_signInServices = httpContext.RequestServices.GetRequiredService<SignInServices>();
            try
            {
                var header = httpContext.Request.Headers;
                if (header.Keys.Contains("Authorization"))
                // && header.Authorization.Equals(SCHEME))
                {
                    Encoding encoding = Encoding.GetEncoding("iso-8859-1");
                    var ass = header.First(x => x.Key.Equals("Authorization")).Value;
                    // Get access token
                    var accessToken = encoding.GetString(Convert.FromBase64String(ass));

                    //var result = _signInServices.SignIn(accessToken);
                    //if (result.isSuccess)
                    //{
                    //    //_httpContext.User = ;
                    //}
                }
            }
            catch (Exception)
            {

                throw;
            }

            return _request.Invoke(httpContext);
        }
    }
}
