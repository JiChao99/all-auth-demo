using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using AllAuthDemo.Filters;
using Microsoft.AspNetCore.Authorization;
using AllAuthDemo.Services;
using Microsoft.AspNetCore.Identity;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.AspNetCore.Authentication.JwtBearer;

namespace AllAuthDemo.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly IUserService _userService;
        public AuthController(IUserService userService)
        {
            _userService = userService;
        }

        [Authorize(AuthenticationSchemes = "Basic")]
        [HttpGet("basic")]
        public ActionResult BasicAuth()
        {
            return Ok(new { Result = "Basic Auth Success" });
        }

        [Authorize(AuthenticationSchemes = "Basic")]
        [HttpGet("basic/user")]
        public ActionResult GetUser()
        {
            return Ok(_userService.Get(int.Parse(User.FindFirstValue(ClaimTypes.NameIdentifier))));
        }

        [Authorize(AuthenticationSchemes = "Digest")]
        [HttpGet("digest")]
        public ActionResult DigestAuth()
        {
            return Ok(new { Result = "Digest Auth OK" });
        }

        [Authorize(AuthenticationSchemes = "Digest")]
        [HttpGet("digest/user")]
        public ActionResult GetUser4Digest()
        {
            return Ok(_userService.Get(int.Parse(User.FindFirstValue(ClaimTypes.NameIdentifier))));
        }

        //[Authorize(AuthenticationSchemes = "test")]
        [HttpGet("session")]
        public async Task<ActionResult> SessionAuth(string userName, string pwd)
        {
            var user = _userService.Authenticate(userName, pwd);
            if (user != null)
            {
                var claims = new List<Claim>
                {
                    new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
                    new Claim(ClaimTypes.Name, user.Name)
                };
                await HttpContext.SignInAsync(new ClaimsPrincipal(new ClaimsIdentity(claims, "Cookies", "user", "role")));
                HttpContext.Session.SetString("AAAAAAAA", DateTime.Now.ToString());
                return Ok(new { Result = $"Sesseion Auth OK {user.Name}" });
            }
            else
            {
                return BadRequest(new { Code = "ErrorUsernameOrPwd", Message = "用户名或密码错误" });
            }

        }

        [Authorize(AuthenticationSchemes = "test")]
        [HttpGet("session/user")]
        public ActionResult GetUser4Session()
        {
            var x = string.Join(",", HttpContext.Session.Keys);
            if (User.Identity.IsAuthenticated)
                return Ok(new { UserInfo = _userService.Get(int.Parse(User.FindFirstValue(ClaimTypes.NameIdentifier))), Session = HttpContext.Session.GetString("AAAAAAAA"), X = x });
            else
            {
                return Unauthorized("Sesseion Auth Fail");
            }
        }
        [Authorize(AuthenticationSchemes = "test")]
        [HttpGet("session/signout")]
        public async Task<ActionResult> SignOut4Session()
        {
            await HttpContext.SignOutAsync();
            HttpContext.Session.Clear();
            return Ok();
        }

        [AllowAnonymous]
        [HttpGet("jwt")]
        public ActionResult JwtAuth(string userName, string pwd)
        {
            var user = _userService.Authenticate(userName, pwd);
            if (user == null)
            {
                return Unauthorized(new { Code = "ErrorUsernameOrPwd", Message = "用户名或密码错误" });
            }
            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
                    new Claim(ClaimTypes.Name, user.Name)
            };
            var token = new JwtSecurityToken(
                "jichao99AllAuth",
                "jichao99AllAuth",
                claims, null,
                DateTime.Now.AddMinutes(15),

                null
            );
            var tokenStr = new JwtSecurityTokenHandler().WriteToken(token);

            return Ok(new { Token = tokenStr, Type = "Bearer " });
        }

        [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
        [HttpGet("jwt/user")]
        public ActionResult GetUser4Jwt()
        {
            return Ok(new { UserInfo = _userService.Get(int.Parse(User.FindFirstValue(ClaimTypes.NameIdentifier))) });
        }
    }
}