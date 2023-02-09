using MongoDB.Bson;
using MongoDB.Bson.Serialization.IdGenerators;
using MongoDB.Driver;
using System.Collections.Generic;
using WebApplication1.Models;

namespace WebApplication1.Services
{
    public interface IAccountServices: IServices<Account>
    {
        //List<Account> Get();
        //Account GetById(string id);
        //Account Create(Account account);
        //Account Update(Account account);
        //void Delete(string id);
    }

    /// <summary>
    /// Intent to use for user login, without google or facebook
    /// </summary>
    public class AccountServices : AbstractServices<Account>, IAccountServices
    {
        public AccountServices(IFinalProjectDatabaseSetting dbSetting, IMongoClient client) : base(dbSetting, client)
        {
        }

        public Account Create(Account account)
        {
            try
            {
                var newAcc = new Account()
                {
                    //ID = _collection.CountDocuments(new BsonDocument()) + 1,
                    UserName = account.UserName,
                    Email = account.Email,
                    Password = account.Password
                };
                _collection.InsertOne(newAcc);

                return newAcc;
            }
            catch (System.Exception)
            {
                return null;
            }
        }

        public void Delete(string id)
        {
            throw new System.NotImplementedException();
        }

        public List<Account> Get()
        {
            var res = _collection.Find(acc => true).ToList();
            return res;
        }

        public Account GetById(string id)
        {
            var res = _collection.Find(s => s.id.Equals(id)).First();
            return res;
        }

        public Account Update(Account newAcc)
        {
            var old = _collection.Find(s => s.id.Equals(newAcc.id)).First();

            // TODO:
            return old;
            //_collection.UpdateOne(Builders<Account>.Filter.Eq(s => s.id, ObjectId.Parse(id)), newAcc);
        }
    }
}
