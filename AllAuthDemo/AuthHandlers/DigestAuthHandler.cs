using AllAuthDemo.Services;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System;
using System.Linq;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text;
using System.Text.Encodings.Web;
using System.Threading.Tasks;

namespace AllAuthDemo.AuthHandlers
{
    public class DigestAuthHandler : AuthenticationHandler<AuthenticationSchemeOptions>
    {
        private readonly IUserService _userService;
        private readonly IMemoryCache _memoryCache;
        public DigestAuthHandler(IOptionsMonitor<AuthenticationSchemeOptions> options,
            ILoggerFactory logger,
            UrlEncoder encoder,
            ISystemClock clock,
            IUserService userService,
            IMemoryCache memoryCache) : base(options, logger, encoder, clock)
        {
            _userService = userService;
            _memoryCache = memoryCache;
        }

        protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            var authValue = Context.GetHeaderAuthValue();
            if (string.IsNullOrEmpty(authValue))
            {
                SetAuthHeader(Context);

                return AuthenticateResult.Fail("Missing Authorization Header");
            }

            var authHeader = AuthenticationHeaderValue.Parse(authValue);
            if (authHeader.Scheme != Constants.Auth.Digest)
            {
                SetAuthHeader(Context);
                return AuthenticateResult.Fail("Error Auth Scheme");
            }
            var hander = GetAuthorizationHeader(authHeader.Parameter);
            if (hander == null)
            {
                SetAuthHeader(Context);
                return AuthenticateResult.Fail("Error Hander");
            }
            var user = _userService.GetUserWithPwd(hander.UserName);
            if (user == null)
            {
                SetAuthHeader(Context);
                return AuthenticateResult.Fail("Error User/Pwd");
            }
            hander.RequestMethod = Context.Request.Method;
            if (!Validate(hander, user.Pwd,out long timestamp))
            {
                SetAuthHeader(Context);
                return AuthenticateResult.Fail("Error Auth Response");
            }
            if (DateTimeOffset.Now.ToUnixTimeSeconds() - timestamp > 60 * 10)
            {
                SetAuthHeader(Context);
                Context.Response.Headers["WWW-Authenticate"] = Context.Response.Headers["WWW-Authenticate"] + ",stale=true";
                return AuthenticateResult.Fail("Error User/Pwd");
            }

            var claims = new[] {
                new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
                new Claim(ClaimTypes.Name, user.Name)
            };
            var identity = new ClaimsIdentity(claims, Scheme.Name);
            var principal = new ClaimsPrincipal(identity);
            var ticket = new AuthenticationTicket(principal, Scheme.Name);

            return AuthenticateResult.Success(ticket);
        }
        private static AuthorizationHeader GetAuthorizationHeader(string authValue)
        {
            var nameValueStrs = authValue.Replace("\"", string.Empty).Split(',', StringSplitOptions.RemoveEmptyEntries).Select(s => s.Trim());
            if (!nameValueStrs.Any())
            {
                return null;
            }

            var result = new AuthorizationHeader();
            foreach (var item in nameValueStrs)
            {
                var index = item.IndexOf('=');
                var name = item[..index];
                var value = item[(index + 1)..];

                switch (name)
                {
                    case Constants.DigestAuthHeaderNames.Realm:
                        result.Realm = value;
                        break;
                    case Constants.DigestAuthHeaderNames.Qop:
                        result.Qop = value;
                        break;
                    case Constants.DigestAuthHeaderNames.ClientNonce:
                        result.ClientNonce = value;
                        break;
                    case Constants.DigestAuthHeaderNames.Nonce:
                        result.Nonce = value;
                        break;
                    case Constants.DigestAuthHeaderNames.NonceCounter:
                        result.NonceCounter = value;
                        break;
                    case Constants.DigestAuthHeaderNames.Response:
                        result.Response = value;
                        break;
                    case Constants.DigestAuthHeaderNames.UserName:
                        result.UserName = value;
                        break;
                    case Constants.DigestAuthHeaderNames.Uri:
                        result.Uri = value;
                        break;
                    default:
                        break;
                };

            }

            return result;
        }

        private static bool Validate(AuthorizationHeader authValue, string userPwd,out long timestamp)
        {
            timestamp = DateTimeOffset.Now.AddMinutes(-10).ToUnixTimeSeconds();

            try
            {
                var nonceStr = Encoding.UTF8.GetString(Convert.FromBase64String(authValue.Nonce));
                var index = nonceStr.IndexOf(":");
                if (index < 0)
                {
                    return false;
                }
                if (!long.TryParse(nonceStr[..nonceStr.IndexOf(":")], out timestamp))
                {
                    return false;
                }
            }
            catch (FormatException)
            {
                return false;
            }

            var a1Hash = $"{authValue.UserName}:{authValue.Realm}:{userPwd}".ToMD5Str();
            var a2Hash = $"{authValue.RequestMethod}:{authValue.Uri}".ToMD5Str();
            return $"{a1Hash}:{GetNonce(timestamp)}:{authValue.NonceCounter}:{authValue.ClientNonce}:{authValue.Qop}:{a2Hash}".ToMD5Str() == authValue.Response;
        }

        private void SetAuthHeader(HttpContext context)
        {
            
            var authValue = new StringBuilder();
            authValue.Append("Digest");
            authValue.Append($" {Constants.DigestAuthHeaderNames.Realm}=\"{Constants.DigestAuthHeaderValues.Realm}\"");
            authValue.Append($" ,{Constants.DigestAuthHeaderNames.Qop}=\"{Constants.QopValues.Auth}\"");
            authValue.Append($" ,{Constants.DigestAuthHeaderNames.Algorithm}=\"{Constants.DigestAuthHeaderValues.Algorithm}\"");
            authValue.Append($" ,{Constants.DigestAuthHeaderNames.Nonce}=\"{GetNonce(DateTimeOffset.Now.ToUnixTimeSeconds())}\"");
            context.Response.Headers.Add("WWW-Authenticate", authValue.ToString());
        }

        private static string GetNonce(long? timestamp)
        {
            timestamp ??= DateTimeOffset.Now.ToUnixTimeSeconds();

            return Convert.ToBase64String(Encoding.UTF8.GetBytes($"{timestamp} :{(timestamp + Constants.DigestAuthHeaderValues.Realm).ToMD5Str()}"));
        }
    }

    public class AuthorizationHeader
    {
        public string UserName { get; set; }
        public string Realm { get; set; }
        public string Nonce { get; set; }
        public string ClientNonce { get; set; }
        public string NonceCounter { get; set; }
        public string Qop { get; set; }
        public string Response { get; set; }
        public string RequestMethod { get; set; }
        public string Uri { get; set; }
    }
    public class XX
    {
        public string Key { get; set; }
        public string Value { get; set; }
    }
}
