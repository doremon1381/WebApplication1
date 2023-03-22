using Google.Apis.Auth;
using Google.Apis.Auth.OAuth2;
using Google.Apis.Auth.OAuth2.Flows;
using Google.Apis.Util.Store;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using WebApplication1.Common;
using WebApplication1.Models.IdentityServer4;
using WebApplication1.Services;

namespace WebApplication1.Controllers
{
    [ApiController]
    [Route("[Controller]")]
    /// <summary>
    /// TODO: will be removed, using authorizationController instead.
    /// </summary>
    public class AuthenticationController : AbstractController<CurrentIdentityUser>
    {
        private GoogleClientSetting _googleSetting;
        private IAuthenticationServices _signinContextServices;
        private ActionController _actionController;

        public AuthenticationController(IAuthorizationThirdPartySetting databaseSetting, IAuthenticationServices signinContextServices, ActionController actionController)
            : base(signinContextServices)
        {
            _signinContextServices = signinContextServices;
            _googleSetting = databaseSetting.Google;
            _actionController = actionController;
        }

        #region Create new account using google's email
        /// <summary>
        /// TODO: get requestCode from client
        /// , do st with access code and id token
        /// , return a cookie to handle authorization from another request after login
        /// </summary>
        [HttpPost("{google}")]
        [Route("auth/google")]
        public ActionResult GoogleLogin([FromBody] JsonElement fromGoogleObj)
        {
            try
            {
                var temp = System.Text.Json.JsonDocument.Parse(fromGoogleObj.GetRawText());
                var requestCode = temp.RootElement.GetProperty("requestCode").ToString();

                var userCredential = GoogleAuthorization(requestCode);

                GoogleJsonWebSignature.Payload idTokenVerified = VerifyingGoogleIdToken(userCredential.Token.IdToken).Result;

                TokenResponse createNewToken;
                if (idTokenVerified != null)
                {
                    // TODO: what to do with this token response
                    createNewToken = (_services as IAuthenticationServices).Create(userCredential.Token);
                }
                else
                {

                }

                // TODO: temporary
                return Ok();
            }
            catch (Exception ex)
            {
                var error = ex.Message;

                // TODO: if "Invalid Grant" is from "The refresh token limit has been exceeded (default is 25)."
                //// https://developers.google.com/accounts/docs/OAuth2#expiration
                //// https://developers.google.com/analytics/devguides/config/mgmt/v3/mgmtAuthorization?#helpme

                return null;
            }
        }

        /// <summary>
        /// TODO: will do something with it later
        ///     , "Invalid Grant" exception can be catched with the error is "The refresh token limit has been exceeded (default is 25)."
        /// </summary>
        /// <param name="requestCode"></param>
        /// <returns></returns>
        private UserCredential GoogleAuthorization(string requestCode)
        {
            // TODO: scope may change in future
            // TODO: does not know what userId use for...
            string userId = Environment.UserName;
            //string redirectUri = "postmessage"; 
            string redirectUri = _googleSetting.RedirectUri;

            string[] scopes = new string[]
            {
                _googleSetting.Scopes
            };

            UserCredential credential;

            // TODO
            IAuthorizationCodeFlow flow = new GoogleAuthorizationCodeFlow(new GoogleAuthorizationCodeFlow.Initializer
            {
                ClientSecrets = new ClientSecrets
                {
                    ClientId = _googleSetting.ClientId,
                    ClientSecret = _googleSetting.ClientSecret
                },
                ProjectId = _googleSetting.ProjectId,
                Scopes = scopes,
                // TODO: dont know what is data store
                DataStore = new FileDataStore("Store")
            });

            Google.Apis.Auth.OAuth2.Responses.TokenResponse token = flow.ExchangeCodeForTokenAsync(userId, requestCode, redirectUri, CancellationToken.None).Result;

            credential = new UserCredential(flow, userId, token);
            return credential;
        }

        private async Task<GoogleJsonWebSignature.Payload> VerifyingGoogleIdToken(string idToken)
        {
            // TODO: following step from: https://developers.google.com/identity/sign-in/web/backend-auth

            // Confirm JWT is valid
            var validPayload = await GoogleJsonWebSignature.ValidateAsync(idToken);

            // pass all, then...
            return validPayload;
        }
        #endregion


        // GET: AccountController
        public ActionResult Index()
        {
            return null;
        }

        // GET: AccountController/Details/5
        public ActionResult Details(int id)
        {
            return null;
        }

        //// GET: AccountController/Create
        //public ActionResult Create()
        //{
        //    return View();
        //}

        [HttpGet]
        [Authorize]
        [Route("/login")]
        public ActionResult Get([FromHeader] string userName, [FromHeader] string password)
        {
            var current = _signinContextServices.GetIdentityByNameAndPassword(userName, password);
            var user = _signinContextServices.GetIdentityUser(current);

            return Ok();
        }

        /// <summary>
        /// POST: AccountController/Create
        /// receive an json object
        /// </summary>
        /// <param name="account"></param>
        /// <returns></returns>
        [HttpPost("{Create}")]
        public ActionResult<CurrentIdentityUser> Create([FromBody] CurrentIdentityUser account)
        {
            try
            {
                var newAcc = _services.Create(account);
                //return RedirectToAction(nameof(Index));
                return newAcc;
            }
            catch (Exception ex)
            {
                // TODO:
                var error = ex.Message;
                return null;
            }
        }

        // TODO:
        // POST: AccountController/Edit/5
        [HttpPost("{Edit}")]
        //[ValidateAntiForgeryToken]
        public ActionResult<CurrentIdentityUser> Edit([FromBody] CurrentIdentityUser account)
        {
            try
            {
                var newAcc = _services.Update(account);
                //return RedirectToAction(nameof(Index));
                return newAcc;
            }
            catch
            {
                return null;
            }
        }

        // POST: AccountController/Delete/5
        [HttpPost("Delete")]
        [ValidateAntiForgeryToken]
        public ActionResult Delete(int id, IFormCollection collection)
        {
            try
            {
                return RedirectToAction(nameof(Index));
            }
            catch
            {
                return null;
            }
        }
    }
}
