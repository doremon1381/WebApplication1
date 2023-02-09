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

        public AbstractServices(IFinalProjectDatabaseSetting dbSetting, IMongoClient client)
        {
            var db = client.GetDatabase(dbSetting.DatabaseName);
            _collection = db.GetCollection<T>(typeof(T).Name);
        }
    }
}
