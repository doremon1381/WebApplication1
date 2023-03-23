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

namespace WebApplication1.Controllers
{
    [ApiController]
    [Route("[Controller]")]
    public class SignInController : ControllerBase
    {
        private ISignInServices _signInServices;

        public SignInController(ISignInServices signInServices)
        {
            _signInServices = signInServices;
        }

        [HttpGet]
        [Route("/login")]
        [AllowAnonymous]
        public ActionResult LoginGetRequest([FromHeader]string Authorization)
        {
            try
            {
                var accessToken = Authorization.Replace("accessToken ", "");
                //var current = _signInServices.GetIdentityByNameAndPassword(userName, password);
                //var user = _signInServices.GetIdentityUser(current);
                var result = _signInServices.SignIn(accessToken);

                return Ok(new { Token = result.securityToken, Message = "Success" });
                //}
            }
            catch (System.Exception)
            {
                return BadRequest("Please pass the valid Username and Password");
            }

            //return Content(identityUser);
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
