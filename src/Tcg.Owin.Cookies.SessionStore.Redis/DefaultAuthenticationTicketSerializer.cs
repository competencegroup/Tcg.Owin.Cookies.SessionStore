using Foundatio.Caching;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;
using Newtonsoft.Json.Linq;
using StackExchange.Redis;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace Tcg.Owin.Cookies.SessionStore.Redis
{


    public static class DefaultAuthenticationTicketSerializer
    {
        public static AuthenticationTicket Deserialize(this string @string)
        {
            if (string.IsNullOrEmpty(@string))
            {
                return null;
            }

            dynamic jsonTicket = JValue.Parse(@string);

            var claims = new List<Claim>();
            foreach (dynamic claim in jsonTicket.Identity.Claims)
            {
                claims.Add(new Claim(claim.Type.ToString(), claim.Value.ToString()));
            }

            var propertiesDict = new Dictionary<string, string>();
            foreach (dynamic prop in jsonTicket.Properties)
            {
                propertiesDict.Add(prop.Key.ToString(), prop.Value.ToString());
            }

            var identity = new ClaimsIdentity(claims, jsonTicket.Identity.AuthenticationType.ToString(), jsonTicket.Identity.NameClaimType.ToString(), jsonTicket.Identity.RoleClaimType.ToString());
            var properties = new AuthenticationProperties(propertiesDict);

            return new AuthenticationTicket(new AcademyIdentity(identity), properties);
        }

        public static string Serialize(this AuthenticationTicket ticket)
        {
            dynamic claims = new JArray();
            foreach (dynamic claim in ticket.Identity.Claims)
            {
                dynamic cl = new JObject();
                cl.Type = claim.Type;
                cl.Value = claim.Value;
                claims.Add(cl);
            }

            dynamic properties = new JArray();
            foreach (var prop in ticket.Properties.Dictionary)
            {
                dynamic p = new JObject();
                p.Key = prop.Key;
                p.Value = prop.Value;
                properties.Add(p);
            }

            dynamic jsonTicket = new JObject();
            jsonTicket.Identity = new JObject();
            jsonTicket.Properties = new JObject();

            jsonTicket.Identity.AuthenticationType = ticket.Identity.AuthenticationType;
            jsonTicket.Identity.RoleClaimType = ticket.Identity.RoleClaimType;
            jsonTicket.Identity.NameClaimType = ticket.Identity.NameClaimType;
            jsonTicket.Identity.Claims = claims;
            jsonTicket.Properties = properties;

            return (jsonTicket as JObject).ToString();
        }
    }
}
