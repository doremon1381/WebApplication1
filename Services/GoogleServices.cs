using MongoDB.Driver;
using WebApplication1.Models.IdentityServer4;
using WebApplication1.Services.Base;

namespace WebApplication1.Services
{
    public interface IGoogleServices
    //: IServices<CurrentIdentityUser>
    {
        TokenResponse Create(Google.Apis.Auth.OAuth2.Responses.TokenResponse gToken);
    }

    public class GoogleServices : AbstractServices<TokenResponse>, IGoogleServices
    {
        public IMongoCollection<TokenResponse> _tokenResponse;

        public GoogleServices(IMongoDatabase database) : base(database)
        {
            _tokenResponse = _collection;
        }

        /// <summary>
        /// Add new token of user's current session to db
        /// </summary>
        /// <param name="document"></param>
        /// <returns></returns>
        /// <exception cref="System.NotImplementedException"></exception>
        public TokenResponse Create(Google.Apis.Auth.OAuth2.Responses.TokenResponse gToken)
        {
            TokenResponse newToken = TokenResponse.MapWithGoogleTokenRespone(gToken);
            try
            {
                _tokenResponse.InsertOne(newToken);

                newToken = _tokenResponse.Find(t => t.AccessToken.Equals(gToken.AccessToken) && t.IdToken.Equals(gToken.IdToken)).First();
            }
            catch (System.Exception ex)
            {
                var ms = ex.Message;
                throw;
            }

            return newToken;
        }
    }
}
