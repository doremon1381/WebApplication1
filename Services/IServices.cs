using MongoDB.Driver;
using System.Collections.Generic;
using WebApplication1.Models;

namespace WebApplication1.Services
{
    public interface IServices<T>
    {
        List<T> Get();
        T GetById(string id);
        T Create(T document);
        T Update(T document);
        void Delete(string id);
    }

    public abstract class AbstractServices<T>
    {
        internal readonly IMongoCollection<T> _collection;

        public AbstractServices(IMongoDatabase mongoDb)
        {
            _collection = mongoDb.GetCollection<T>(typeof(T).Name);
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
}
