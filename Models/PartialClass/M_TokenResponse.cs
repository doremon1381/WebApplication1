using WebApplication1.Models;

namespace WebApplication1.Models
{
    public partial class TokenResponse
    {
        public TokenResponse Create(TokenResponse document)
        {
            TokenResponse news = new TokenResponse()
            {
                //AccessToken = document.Acc
            };

            return null;
        }

        public static TokenResponse MapWithGoogleTokenRespone(Google.Apis.Auth.OAuth2.Responses.TokenResponse gToken)
        {
            var newToken = new TokenResponse()
            {
                AccessToken = gToken.AccessToken,
                IdToken = gToken.IdToken,
                TokenType = gToken.TokenType,
                Scopes = gToken.Scope,
                RefreshToken = gToken.RefreshToken,
                ExpiresInSeconds = gToken.ExpiresInSeconds ?? 0
            };

            return newToken;
        }
    }
}
