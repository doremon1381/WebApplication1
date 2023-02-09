using Google.Apis.Auth;
using Google.Apis.Auth.OAuth2;
using Google.Apis.Auth.OAuth2.Flows;
using Google.Apis.Util.Store;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using WebApplication1.Models;
using WebApplication1.Services;

namespace WebApplication1.Controllers
{
    [ApiController]
    [Route("[controller]")]
    //[Route("/Authorizing")]
    public class AuthorizingController : AbstractController<TokenResponse>
    {
        private GoogleAuthorizationSetting _googleSetting;
        private IDataProtectionProvider _protectionProvider;
        private readonly IWebHostEnvironment _hostingEnvironment;

        public AuthorizingController(IAuthorizationServices services, IAuthorizationThirdPartySetting authorizationSetting, IWebHostEnvironment hostingEnvironment, IDataProtectionProvider protectionProvider) : base(services)
        {
            _googleSetting = authorizationSetting.Google;
            _hostingEnvironment = hostingEnvironment;
            _protectionProvider = protectionProvider;
        }

        #region Create new account using google's email
        /// <summary>
        /// TODO: get requestCode from client
        /// , do st with access code and id token
        /// , return a cookie to handle authorization from another request after login
        /// </summary>
        [HttpPost("{google}")]
        //[Route("/google")]
        public ActionResult GoogleLogin([FromBody]JsonElement fromGoogleObj)
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
                    createNewToken = (_services as IAuthorizationServices).Create(userCredential.Token); 
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

        [HttpGet]
        public void GoogleLogin()
        {
            var protector = _protectionProvider.CreateProtector("Oauth");
            //var code = new Authcode();
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
