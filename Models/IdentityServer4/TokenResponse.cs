using MongoDB.Bson;
using MongoDB.Bson.Serialization.Attributes;
using System;
using WebApplication1.Models.Base;

namespace WebApplication1.Models.IdentityServer4
{
    public partial class TokenResponse: BasicModel
    {
        [BsonElement("Date")]
        public string Date { get; set; }
        [BsonElement("AccessToken")]
        public string AccessToken { get; set; }
        [BsonElement("ExpiresIn")]
        public long ExpiresInSeconds { get; set; }
        [BsonElement("RefreshToken")]
        public string RefreshToken { get; set; }
        [BsonElement("Scopes")]
        public string Scopes { get; set; }
        [BsonElement("IdToken")]
        public string IdToken { get; set; }
        [BsonElement("TokenType")]
        public string TokenType { get; set; }

        [BsonIgnore]
        public TimeSpan ExpiresIn => TimeSpan.FromSeconds(ExpiresInSeconds);
    }
}
