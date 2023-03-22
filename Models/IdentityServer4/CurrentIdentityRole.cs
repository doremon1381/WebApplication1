using AspNetCore.Identity.MongoDbCore.Models;
using MongoDB.Bson;

namespace WebApplication1.Models.IdentityServer4
{
    public class CurrentIdentityRole : MongoIdentityRole<ObjectId>
    {
    }
}
