using System;
using System.IO;

using Microsoft.Extensions.Options;

using NetCasbin;
using NetCasbin.Model;

namespace Casbin.AspNetCore.Authorization
{
    public class DefaultCasbinModelProvider : ICasbinModelProvider
    {
        private readonly IOptions<CasbinAuthorizationOptions> _options;
        private Model? _model;
        private Model _fallcackModel = Model.CreateDefaultFromText(@"
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[role_definition]
g = _, _
g2 = _, _

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = (p.sub == ""*"" || g(r.sub, p.sub)) && (p.obj == ""*"" || g2(r.obj, p.obj)) && (p.act == ""*"" || r.act == p.act)
");

        public DefaultCasbinModelProvider(IOptions<CasbinAuthorizationOptions> options)
        {
            _options = options ?? throw new ArgumentNullException(nameof(options));
        }

        public virtual Model? GetModel()
        {
            if (_model is not null)
            {
                return _model;
            }

            if (_options.Value.DefaultEnforcerFactory is not null)
            {
                return null;
            }

            // it will changed at next Casbin.NET version (v1.3.2 or later)
            _model ??= this._fallcackModel;
            return _model;
        }
    }
}
