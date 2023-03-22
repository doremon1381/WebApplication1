using AspNetCore.Identity.MongoDbCore.Models;
using Microsoft.AspNetCore.DataProtection.KeyManagement;
using Microsoft.AspNetCore.Identity;
using MongoDB.Bson;
using MongoDB.Bson.Serialization.Attributes;
using System;

namespace WebApplication1.Models.IdentityServer4
{
    /// <summary>
    /// Is MongoUser, as IdentityUser's role of Asp.net core
    /// </summary>
    public partial class CurrentIdentityUser: MongoIdentityUser<ObjectId>
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
        //[BsonElement("CustomClaims")]
        //public System.Collections.Generic.List<MongoIdentityUserClaim> CustomClaims { get; set; }
        //[BsonElement("GoogleClientId")]
        //public string GoogleClientId { get; set; }

        [BsonIgnore]
        public bool IsLoginWithUserName { get; set; }
    }
}
