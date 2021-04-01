using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace AllAuthDemo.Services
{
    public interface IUserService
    {
        User Authenticate(string userName, string password);
        List<User> GetAll();

        User Get(int id);

        User GetUserWithPwd(string userName);
    }
}
