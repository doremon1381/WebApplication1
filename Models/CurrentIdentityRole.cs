using AspNetCore.Identity.MongoDbCore.Models;
using MongoDB.Bson;

namespace WebApplication1.Models
{
    public class CurrentIdentityRole : MongoIdentityRole<ObjectId>
    {
    }
}
