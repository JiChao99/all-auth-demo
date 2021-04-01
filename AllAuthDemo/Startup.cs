using AllAuthDemo.AuthHandlers;
using AllAuthDemo.Filters;
using AllAuthDemo.Services;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.HttpsPolicy;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.OpenApi.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.Extensions.Caching.Redis;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using System.Text;

namespace AllAuthDemo
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {

            //services.AddControllers(option => option.Filters.Add<BasicAuthFilterAttribute>());
            services.AddControllers();
            services.AddTransient<IUserService, UserService>();

            services.AddDistributedMemoryCache();

            //services.AddDistributedRedisCache(options =>
            //{
            //    options.Configuration = "localhost";
            //    options.InstanceName = "jichao99AllAuth";
            //});
            services.AddSession();

            services.AddSwaggerGen(c =>
            {
                c.SwaggerDoc("v1", new OpenApiInfo { Title = "AllAuthDemo", Version = "v1" });
            });
            services.AddAuthentication(option =>
            {
                option.AddScheme("Basic", builder => builder.HandlerType = typeof(BasicAuthHandler));
                option.AddScheme("Digest", builder => builder.HandlerType = typeof(DigestAuthHandler));
                option.AddScheme("Session", builder => builder.HandlerType = typeof(SessionAuthHandler));
            }).AddCookie();


            services.AddAuthentication("test") // Sets the default scheme to cookies
                .AddCookie("test", options =>
                {
                    //options.AccessDeniedPath = "/account/denied";
                    options.LoginPath = "/api/auth/session";
                });


            services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
                .AddJwtBearer(options =>
                {
                    options.SaveToken = true;
                    options.TokenValidationParameters = new TokenValidationParameters
                    {
                        ValidateIssuer = true,
                        ValidIssuer = "jichao99AllAuth",
                        ValidateAudience = true,
                        ValidAudience = "jichao99AllAuth",
                        ValidateIssuerSigningKey = true,
                        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("jichao99AllAuth"))
                    };
                });
            services.AddMemoryCache();
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }
            app.UseSwagger();
            app.UseSwaggerUI(c => c.SwaggerEndpoint("/swagger/v1/swagger.json", "AllAuthDemo v1"));

            app.UseHttpsRedirection();

            app.UseRouting();

            app.UseAuthorization();
            app.UseAuthentication();

            app.UseSession();

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllers();
            });
        }
    }
}
