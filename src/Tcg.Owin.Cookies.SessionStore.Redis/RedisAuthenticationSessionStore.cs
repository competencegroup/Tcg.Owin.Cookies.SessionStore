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
    public class RedisAuthenticationSessionStore : IAuthenticationSessionStore
    {
        RedisCacheClient _client;
        public RedisAuthenticationSessionStore(string connectionString)
        {
            var muxer = ConnectionMultiplexer.Connect(connectionString);

            _client = new RedisCacheClient(new RedisCacheClientOptions
            {
                ConnectionMultiplexer = muxer
            });
        }
        public Task RemoveAsync(string key)
        {
            return _client.RemoveAsync(key);
        }

        DateTime? GetExpiration(AuthenticationTicket ticket)
        {
            var expiresAt = default(DateTime?);
            if (ticket.Properties.ExpiresUtc.HasValue)
            {
                expiresAt = ticket.Properties.ExpiresUtc.Value.UtcDateTime;
            }
            return expiresAt;
        }

        public Task RenewAsync(string key, AuthenticationTicket ticket)
        {
            return _client.ReplaceAsync(key, ticket.Serialize(), GetExpiration(ticket));
        }

        public async Task<AuthenticationTicket> RetrieveAsync(string key)
        {
            var cacheValue = await _client.GetAsync<string>(key);
            return cacheValue.HasValue ? cacheValue.Value.Deserialize() : null;
        }

        public async Task<string> StoreAsync(AuthenticationTicket ticket)
        {
            var key = Guid.NewGuid().ToString("N");

            await _client.AddAsync(key, ticket.Serialize(), GetExpiration(ticket));

            return key;
        }
    }
}
