using System;
using System.Security.Claims;
using NetCasbin;
using NetCasbin.Model;

namespace Casbin.AspNetCore.Authorization
{
    public class CasbinAuthorizationOptions
    {
        public Func<Model?, Enforcer>? DefaultEnforcerFactory { get; set; }
        public string PreferSubClaimType { get; set; } = ClaimTypes.NameIdentifier;
        public IRequestTransformer? DefaultRequestTransformer { get; set; }
    }
}
