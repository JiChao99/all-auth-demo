using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace AllAuthDemo.Services
{
    public class UserService : IUserService
    {
        private readonly List<User> _users = new List<User>
        {
            new User
            {
                Age = 10,
                Email = "tom@temp.temp",
                Id = 1,
                Mobile = "13300006666",
                Name = "Tom",
                Pwd = "tommm",
                Md5Pwd = "bfb99c7a1baea68729f097e5dba5a09a"

            },
            new User
            {
                Age = 20,
                Email = "Jerry@temp.temp",
                Id = 2,
                Mobile = "13300009999",
                Name = "Jerry",
                Pwd = "jerryy",
                Md5Pwd="f89ea4775faaa57b48336fbaf7106bfb"
            }
        };

        public User Authenticate(string name, string pwd)
        {
            return _users.FirstOrDefault(t => t.Name == name && t.Pwd == pwd);
        }

        public User Get(int id)
        {
            var result = _users.FirstOrDefault(t => t.Id == id);

            if (result is null)
            {
                return result;
            }
            result.Pwd = null;
            result.Md5Pwd = null;

            return result;
        }

        public User GetUserWithPwd(string userName)
        {
            return _users.FirstOrDefault(t => t.Name == userName);
        }

        public List<User> GetAll()
        {
            var result = _users;
            result.ForEach(t => { t.Pwd = null; t.Md5Pwd = null; });

            return result;
        }
    }
}
