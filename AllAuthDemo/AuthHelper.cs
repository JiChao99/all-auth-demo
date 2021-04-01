using Microsoft.AspNetCore.Http;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security;

namespace AllAuthDemo
{
    public static class AuthHelper
    {
        public static string GetHeaderAuthValue(this HttpContext context)
        {
            var authKey = "Authorization";
            return context.Request.Headers.Keys.Contains(authKey) ? context?.Request?.Headers[authKey] : null;
        }

        public static string ToMD5Str(this string data)
        {
            using System.Security.Cryptography.MD5 mD = System.Security.Cryptography.MD5.Create();
            byte[] value = mD.ComputeHash(Encoding.UTF8.GetBytes(data));
            return BitConverter.ToString(value).Replace("-", "").ToLower();
        }
    }
}
