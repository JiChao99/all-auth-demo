using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AllAuthDemo.Filters
{
    public class BasicAuthFilterAttribute : AuthorizeAttribute, IAuthorizationFilter
    {

        
        public void OnAuthorization(AuthorizationFilterContext context)
        {
            var headerAuthValue = GetHeaderAuthValue(context.HttpContext, "Authorization");
            if (string.IsNullOrEmpty(headerAuthValue))
            {
                SetWWWAuth(context);
                return;
            }
            if (!CheckUser(headerAuthValue))
            {
                SetWWWAuth(context);
                return;
            }
        }

        private static string GetHeaderAuthValue(HttpContext context, string authKey)
        {
            return context.Request.Headers.Keys.Contains(authKey) ? context?.Request?.Headers[authKey] : null;
        }

        private bool CheckUser(string headerAuthValue)
        {
            if (!headerAuthValue.StartsWith("Basic "))
            {
                return false;
            }
            var base64Str = headerAuthValue.Substring("Basic ".Length);

            var bytes = Convert.FromBase64String(base64Str);
            var decodeStr = Encoding.Default.GetString(bytes);

            var user = decodeStr.Split(":");
            if (user.Length != 2)
            {
                return false;
            }
            var users = new List<User>
            {
                new User{ UserName="123",Pwd= "456"}
            };

            if (!users.Any(t => t.UserName == user[0] && t.Pwd == user[1]))
            {
                return false;
            }
            return true;
        }

        private void SetWWWAuth(AuthorizationFilterContext context)
        {
            context.HttpContext.Response.StatusCode = 401;
            context.HttpContext.Response.Headers.Add("WWW-Authenticate", $"Basic Realm=\"alec test\"");
            context.Result = new UnauthorizedResult();
        }

        public Task HandleAsync(AuthorizationHandlerContext context)
        {
            throw new NotImplementedException();
        }
    }

    internal class User
    {
        public string UserName { get; set; }
        public string Pwd { get; set; }
    }
}
