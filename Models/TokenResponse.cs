using MongoDB.Bson;
using MongoDB.Bson.Serialization.Attributes;
using MongoDB.Bson.Serialization.IdGenerators;
using System;

namespace WebApplication1.Models
{
    public partial class TokenResponse: BasicModel
    {
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
