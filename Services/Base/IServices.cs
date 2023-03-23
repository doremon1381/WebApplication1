using MongoDB.Driver;
using System.Collections.Generic;
using WebApplication1.Models;

namespace WebApplication1.Services.Base
{
    public interface IServices<T>
    {
        List<T> Get();
        T GetById(string id);
        T Create(T document);
        T Update(T document);
        void Delete(string id);
    }
}
