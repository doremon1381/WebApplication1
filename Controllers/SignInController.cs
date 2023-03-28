using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System;
using WebApplication1.Models;
using WebApplication1.Models.IdentityServer4;
using WebApplication1.Services;
using Serilog;
using Microsoft.AspNetCore.Mvc.Infrastructure;
using WebApplication1.Common;

namespace WebApplication1.Controllers
{
    [ApiController]
    [Route("[Controller]")]
    public class SignInController : ControllerBase
    {
        private ISignInServices _signInServices;
        private ActionWithLog<string, ActionResult> _loginGetRequestCommand;

        public SignInController(ISignInServices signInServices, ILogger logger)
        {
            _signInServices = signInServices;

            // TODO:
            //_actionHandler = actionHandler;
            _loginGetRequestCommand = new ActionWithLog<string, ActionResult>((authorization) => { return LoginGetRequest(authorization); }, "LoginGetRequest", logger);
        }

        // TODO:
        /// <summary>
        /// TODO: parameter's name is Authorization is temporary
        /// </summary>
        /// <param name="Authorization"></param>
        /// <returns></returns>
        [HttpGet]
        [Route("/api/login")]
        [AllowAnonymous]
        public ActionResult LoginGetRequestCommand([FromHeader] string Authorization)
        {
            return _loginGetRequestCommand.Excute(Authorization);
        }

        /// <summary>
        /// TODO: need to implement "HTTP Authentication Basic access authentication"
        /// </summary>
        /// <param name="accessToken"></param>
        /// <returns></returns>
        private ActionResult LoginGetRequest(string accessToken)
        {
            var at = accessToken.Replace("accessToken ", "");

            var result = _signInServices.SignIn(at);

            return Ok(new { Token = result.securityToken, Message = "Success" });
        }

        [HttpGet]
        [Route("/getUser")]
        [Authorize]
        public ActionResult GetUser()
        {
            return Content("OK");
        }


        /// <summary>
        /// WARNING: testing
        /// </summary>
        /// <returns></returns>
        [HttpPost]
        [Route("/login")]
        [AllowAnonymous]
        public ActionResult Login([FromHeader] string Authorization)
        {
            // TODO: not done
            //_actionController.Run((a) =>
            //{
            //    var user = _signinContextServices.GetByUserNameAndPassword(a.userName, a.password);
            //    _signinContextServices.SignIn(user);
            //    return true;
            //}, (userName: userName, password, password: userName, password));

            // TODO: inform IS4's sdk in appServices to deserialize accesstoken to get information
            //var user = _signinContextServices.GetByUserNameAndPassword(userName, password);
            //_signinContextServices.SignIn(user);

            return Ok();
        }
    }
}
