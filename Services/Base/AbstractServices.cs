using MongoDB.Driver;

namespace WebApplication1.Services.Base
{
    public abstract class AbstractServices<T>
    {
        internal readonly IMongoCollection<T> _collection;

        public AbstractServices(IMongoDatabase mongoDb)
        {
            _collection = mongoDb.GetCollection<T>(typeof(T).Name);
        }
    }

    public abstract class AbstractServices<T, T1>
    {
        internal readonly IMongoCollection<T> _collection;
        internal readonly IMongoCollection<T1> _collection1;

        public AbstractServices(IMongoDatabase mongoDb)
        {
            _collection = mongoDb.GetCollection<T>(typeof(T).Name);
            _collection1 = mongoDb.GetCollection<T1>(typeof(T1).Name);
        }
    }

    public abstract class AbstractServices<T, T1, T2>
    {
        internal readonly IMongoCollection<T> _collection;
        internal readonly IMongoCollection<T1> _collection1;
        internal readonly IMongoCollection<T2> _collection2;

        public AbstractServices(IMongoDatabase mongoDb)
        {
            _collection = mongoDb.GetCollection<T>(typeof(T).Name);
            _collection1 = mongoDb.GetCollection<T1>(typeof(T1).Name);
            _collection2 = mongoDb.GetCollection<T2>(typeof(T2).Name);
        }
    }

    public abstract class AbstractServices<T, T1, T2, T3>
    {
        internal readonly IMongoCollection<T> _collection;
        internal readonly IMongoCollection<T1> _collection1;
        internal readonly IMongoCollection<T2> _collection2;
        internal readonly IMongoCollection<T3> _collection3;

        public AbstractServices(IMongoDatabase mongoDb)
        {
            _collection = mongoDb.GetCollection<T>(typeof(T).Name);
            _collection1 = mongoDb.GetCollection<T1>(typeof(T1).Name);
            _collection2 = mongoDb.GetCollection<T2>(typeof(T2).Name);
            _collection3 = mongoDb.GetCollection<T3>(typeof(T3).Name);
        }
    }
}
