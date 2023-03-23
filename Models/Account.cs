using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;

namespace WebApplication1.Models
{
    /// <summary>
    /// use for sending account information to web client
    /// </summary>
    public class Account
    {
        public JwtHeader JwtHeader { get; private set; }
        /// <summary>
        /// nbf: not valid before
        /// </summary>
        public Dictionary<int?, DateTime> NotValidBefore { get; private set; }
        /// <summary>
        /// exp: Expiration Time
        /// </summary>
        public Dictionary<int?, DateTime> ExpirationTime { get; private set; }
        /// <summary>
        /// iss: who created and signed this token
        /// </summary>
        public string Issuer { get; private set; }
        /// <summary>
        /// client_id 
        /// </summary>
        public string ClientId { get; private set; }
        /// <summary>
        /// sub: whom this token refer to
        /// </summary>
        public string Subject { get; private set; }
        /// <summary>
        /// auth_time: time when authentication occurred
        /// </summary>
        public Dictionary<int?, DateTime> AuthenticationTime { get; private set; } = new Dictionary<int?, DateTime>();
        /// <summary>
        /// idp
        /// </summary>
        public string IdentityProvider { get; private set; }
        /// <summary>
        /// jti: Identity Unique Token
        /// </summary>
        public string JWTID { get; private set; }
        /// <summary>
        /// iat: issued at
        /// </summary>
        public DateTime IssuedAt { get; private set; }
        /// <summary>
        /// scope
        /// </summary>
        public List<string> Scope { get; private set; }
        /// <summary>
        /// arm: authentication method array
        /// </summary>
        public List<string> AuthenticationMethodArray { get; private set; }

        public Account()
        {

        }

        public void GetFromAccessToken(JwtSecurityToken token)
        {
            this.JwtHeader = token.Header;
            this.NotValidBefore = new Dictionary<int?, DateTime>() { { token.Payload.Nbf, (token.Payload.Nbf.HasValue ? DateTime.FromBinary(long.Parse(token.Payload.Nbf.ToString())) : DateTime.Now) } };
            this.ExpirationTime = new Dictionary<int?, DateTime>() { { token.Payload.Exp, (token.Payload.Exp.HasValue ? DateTime.FromBinary(long.Parse(token.Payload.Exp.ToString())) : DateTime.Now) } };
            this.Issuer = token.Issuer;
            this.IssuedAt = token.IssuedAt;
            this.ClientId = AppSettingExtensions.ClientId;
            this.Subject = token.Subject;
            this.AuthenticationTime = new Dictionary<int?, DateTime>()
                {
                    { token.Payload.AuthTime, (token.Payload.AuthTime.HasValue ? DateTime.FromBinary(long.Parse(token.Payload.AuthTime.ToString())) : DateTime.Now) }
                };
            this.Scope = new List<string>();
            this.AuthenticationMethodArray = new List<string>(token.Payload.Amr);
        }
    }

    /// <summary>
    /// TODO: will check again
    /// </summary>
    public interface IAccount // use for save payload from an jwt's accesstoken
    {
        /// <summary>
        /// nbf: not valid before
        /// </summary>
        public string NotValidBefore { get; set; }
        /// <summary>
        /// exp
        /// </summary>
        public string ExpirationTime { get; set; }
        /// <summary>
        /// iss: who created and signed this token
        /// </summary>
        public string Issuer { get; set; }
        /// <summary>
        /// client_id 
        /// </summary>
        public string ClientId { get; set; }
        /// <summary>
        /// sub: whom this token refer to
        /// </summary>
        public string Sub { get; set; }
        /// <summary>
        /// auth_time: time when authentication occurred
        /// </summary>
        public string AuthenticationTime { get; set; }
        /// <summary>
        /// idp
        /// </summary>
        public string IdentityProvider { get; set; }
        /// <summary>
        /// jti: Identity Unique Token
        /// </summary>
        public string JWTID { get; set; }
        /// <summary>
        /// iat: issued at
        /// </summary>
        public string IssuedAt { get; set; }
        /// <summary>
        /// scope
        /// </summary>
        public List<string> Scope { get; set; }
        /// <summary>
        /// arm: authentication method array
        /// </summary>
        public string AuthenticationMethodArray { get; set; }
    }
}
