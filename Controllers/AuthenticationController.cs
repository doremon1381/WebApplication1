using Google.Apis.Auth;
using Google.Apis.Auth.OAuth2;
using Google.Apis.Auth.OAuth2.Flows;
using Google.Apis.Util.Store;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc;
using MongoDB.Driver;
using System;
using System.Linq;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using WebApplication1.Models;
using WebApplication1.Services;

namespace WebApplication1.Controllers
{
    /// <summary>
    /// REMARK: this controller can be used as function of one webApplication (object of thinking)
    ///       : but, if seperate Authentication server and resource server, I think this controller should belong to Authentication server
    /// </summary>
    [ApiController]
    [Route("auth")]
    public class AuthenticationController : ControllerBase
    //: AbstractController<TokenResponse>
    {
        private GoogleClientSetting _googleSetting;
        private IAuthenticationServices _authenticationServices;
        //private IDataProtectionProvider _protectionProvider;
        //private readonly IWebHostEnvironment _hostingEnvironment;

        public AuthenticationController(IAuthenticationServices authenticationService, IAuthorizationThirdPartySetting authorizationSetting, IAuthenticationServices services) 
            //: base(services)
        {
            _googleSetting = authorizationSetting.Google;
            _authenticationServices = authenticationService;
            //_hostingEnvironment = hostingEnvironment;
            //_protectionProvider = protectionProvider;
        }

        //private Account GetAccount()
        //{
        //    var account = _services.GetById
        //}

        /// <summary>
        /// WARNING: testing
        /// </summary>
        /// <returns></returns>
        [HttpPost]
        [Route("auth/signup")]
        public ActionResult Signup()
        {
            //var protector = _protectionProvider.CreateProtector("Oauth");
            //var code = new Authcode();

            return new JsonResult(from c in User.Claims select new { c.Type, c.Value });
        }

        /// <summary>
        /// WARNING: testing
        /// </summary>
        /// <returns></returns>
        [HttpGet]
        public JsonResult Get()
        {
            //var protector = _protectionProvider.CreateProtector("Oauth");
            //var code = new Authcode();

            return new JsonResult(from c in User.Claims select new { c.Type, c.Value });
        }

        /// <summary>
        /// get token and return access code
        /// </summary>
        [HttpPost]
        [Route("/facebook")]
        public void FacebookLogin()
        {

        }

        [HttpPost]
        [Route("/google-logout")]
        public void Logout([FromBody] string accessToken)
        {

        }
    }
}
