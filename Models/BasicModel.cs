using MongoDB.Bson;
using MongoDB.Bson.Serialization.Attributes;
using MongoDB.Bson.Serialization.IdGenerators;

namespace WebApplication1.Models
{
    // TODO: intend to use for any other class of object as collection defined in mongodb, but not yet find a correct solution
    public class BasicModel
    {
        [BsonId(IdGenerator = typeof(ObjectIdGenerator))]
        [BsonRepresentation(BsonType.ObjectId)]
        public ObjectId id { get; set; }
    }
}
