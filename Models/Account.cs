using AspNetCore.Identity.Mongo.Model;
using MongoDB.Bson;
using MongoDB.Bson.Serialization.Attributes;
using System;

namespace WebApplication1.Models
{
    public partial class Account: MongoUser
    {
        //[BsonId(IdGenerator = typeof(ObjectIdGenerator))]
        //[BsonRepresentation(BsonType.ObjectId)]
        //public ObjectId id { get; set; }
        [BsonElement("Name")]
        public string Name { get; set; } = string.Empty;
        //[BsonElement("UserName")]
        //public string UserName { get; set; } = string.Empty;
        //[BsonElement("Email")]
        //public string Email { get; set; } = string.Empty;
        [BsonElement("Facebook")]
        public string Facebook { get; set; } = string.Empty;
        [BsonElement("Password")]
        public string Password { get; set; } = string.Empty;
        [BsonElement("Address")]
        public string Address { get; set; } = string.Empty;
        // TODO: 
        [BsonElement("TokenResponseIds")]
        public BsonDocument TokenResponseIds { get; set; }
        // TODO: 
        [BsonElement("apis")]
        public System.Collections.Generic.List<string> Apis { get; set; }
        //[BsonElement("GoogleClientId")]
        //public string GoogleClientId { get; set; }

        [BsonIgnore]
        public bool IsLoginWithUserName { get; set; }
    }

    //public class MongoRole : MongoRole
    //{

    //}
}
