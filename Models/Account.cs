using MongoDB.Bson;
using MongoDB.Bson.Serialization.Attributes;
using MongoDB.Bson.Serialization.IdGenerators;
using System.Collections.Generic;

namespace WebApplication1.Models
{
    public class Account: BasicModel
    {
        [BsonElement("UserName")]
        public string UserName { get; set; } = string.Empty;
        [BsonElement("Email")]
        public string Email { get; set; } = string.Empty;
        [BsonElement("Password")]
        public string Password { get; set; } = string.Empty;
        // TODO: 
        [BsonElement("TokenResponseIds")]
        public IDictionary<int, ObjectId> TokenResponseIds { get; set; }
        [BsonElement("GoogleClientId")]
        public string GoogleClientId { get; set; }

        [BsonIgnore]
        public bool IsLoginWithUserName { get; set; }
    }
}
