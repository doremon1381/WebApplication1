using System.Collections.Generic;
using WebApplication1.Models;

namespace WebApplication1.Services
{
    public interface ISignInServices: IServices<Account>
    {
        void SignIn(Account user);

    }

    public class SignInServices : ISignInServices
    {
        public Account Create(Account document)
        {
            throw new System.NotImplementedException();
        }

        public void Delete(string id)
        {
            throw new System.NotImplementedException();
        }

        public List<Account> Get()
        {
            throw new System.NotImplementedException();
        }

        public Account GetById(string id)
        {
            throw new System.NotImplementedException();
        }

        public void SignIn(Account user)
        {
            throw new System.NotImplementedException();
        }

        public Account Update(Account document)
        {
            throw new System.NotImplementedException();
        }
    }
}
