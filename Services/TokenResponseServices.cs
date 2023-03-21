using System.Collections.Generic;
using WebApplication1.Models;

namespace WebApplication1.Services
{
    public interface ITokenResponseServices: IServices<TokenResponse>
    {
    }

    public class TokenResponseServices : ITokenResponseServices
    {
        public TokenResponse Create(TokenResponse document)
        {
            throw new System.NotImplementedException();
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
