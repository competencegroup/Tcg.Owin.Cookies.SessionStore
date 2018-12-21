using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;

namespace Tcg.Owin.Cookies.SessionStore.Redis
{

    public class AcademyIdentity : ClaimsIdentity
    {
        readonly Lazy<HashSet<string>> _roles;
        public AcademyIdentity(ClaimsIdentity other)
            : base(other)
        {
            _roles = new Lazy<HashSet<string>>(() =>
            {
                var roles = other.FindAll(other.RoleClaimType).Select(x => x.Value);
                return new HashSet<string>(roles, StringComparer.OrdinalIgnoreCase);
            });
        }
        public override bool HasClaim(string type, string value)
        {
            if (type == RoleClaimType)
                return _roles.Value.Contains(value);

            return base.HasClaim(type, value);
        }
    }
}
