using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace AllAuthDemo.Constants
{
    public static class DigestAuthHeaderNames
    {
        public const string UserName = "username";
        public const string Realm = "realm";
        public const string Nonce = "nonce";
        public const string ClientNonce = "cnonce";
        public const string NonceCounter = "nc";
        public const string Qop = "qop";
        public const string Response = "response";
        public const string Uri = "uri";
        public const string RspAuth = "rspauth";
        public const string Stale = "stale";
        public const string Algorithm = "algorithm";
    }

    public static class DigestAuthHeaderValues
    {
        public const string Realm = "github.com/jichao99/auth";
        public const string Algorithm = "md5";
    }

    public static class QopValues
    {
        public const string Auth = "auth";
        public const string AuthInt = "auth-int";
    }

    public static class Auth
    {
        public const string WWWAuthHeaderKey = "WWW-Authenticate";
        public const string Digest = nameof(Digest);
        public const string Basic = nameof(Basic);
    }
}
