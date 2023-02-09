using MongoDB.Driver;
using System.Collections.Generic;
using WebApplication1.Models;

namespace WebApplication1.Services
{
    public interface IAuthorizationServices : IServices<TokenResponse>
    {
        TokenResponse Create(Google.Apis.Auth.OAuth2.Responses.TokenResponse gToken);
    }

    /// <summary>
    /// intent to use for google or facebook
    /// </summary>
    public class AuthorizingServices : AbstractServices<TokenResponse>, IAuthorizationServices
    {
        public AuthorizingServices(IFinalProjectDatabaseSetting dbSetting, IMongoClient client) : base(dbSetting, client)
        {
        }

        /// <summary>
        /// TODO: implement, but may not use
        /// </summary>
        /// <param name="document"></param>
        /// <returns></returns>
        /// <exception cref="System.NotImplementedException"></exception>
        public TokenResponse Create(TokenResponse document)
        {
            throw new System.NotImplementedException();
        }

        /// <summary>
        /// Add new token of user's current session to db
        /// </summary>
        /// <param name="document"></param>
        /// <returns></returns>
        /// <exception cref="System.NotImplementedException"></exception>
        public TokenResponse Create(Google.Apis.Auth.OAuth2.Responses.TokenResponse gToken)
        {
            var newToken = TokenResponse.MapWithGoogleTokenRespone(gToken);
            try
            {
                _collection.InsertOne(newToken);

                newToken = _collection.Find(t => t.AccessToken.Equals(gToken.AccessToken) && t.IdToken.Equals(gToken.IdToken)).First();
            }
            catch (System.Exception ex)
            {
                var ms = ex.Message;
                throw;
            }

            return newToken;
        }

        public void Delete(string id)
        {
            throw new System.NotImplementedException();
        }

        public List<TokenResponse> Get()
        {
            throw new System.NotImplementedException();
        }

        public TokenResponse GetById(string id)
        {
            throw new System.NotImplementedException();
        }

        public TokenResponse Update(TokenResponse document)
        {
            throw new System.NotImplementedException();
        }
    }
}
