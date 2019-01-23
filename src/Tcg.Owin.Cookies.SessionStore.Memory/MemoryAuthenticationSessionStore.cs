using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace Tcg.Owin.Cookies.SessionStore.Memory
{
    public class MemoryAuthenticationSessionStore : IAuthenticationSessionStore
    {
        static readonly object _lock = new object();
        static readonly Dictionary<string, AuthenticationTicket> _cache = new Dictionary<string, AuthenticationTicket>();
        static readonly Timer _timer = new Timer(OnTimer, null, TimeSpan.Zero, TimeSpan.FromMinutes(1));

        private static void OnTimer(object state)
        {
            lock (_lock)
            {
                var expiredKeys = _cache
                    .Where(x => x.Value.Properties.ExpiresUtc.HasValue && x.Value.Properties.ExpiresUtc.Value < DateTimeOffset.UtcNow)
                    .Select(x => x.Key)
                    .ToList();

                foreach (var expiredKey in expiredKeys)
                {
                    _cache.Remove(expiredKey);
                }
            }
        }

        public Task RemoveAsync(string key)
        {
            lock(_lock)
            {
                _cache.Remove(key);
            }
            
            return Task.FromResult(0);
        }

        public Task RenewAsync(string key, AuthenticationTicket ticket)
        {
            lock (_lock)
            {
                _cache[key] = ticket;
            }

            return Task.FromResult(0);
        }

        public Task<AuthenticationTicket> RetrieveAsync(string key)
        {
            lock (_lock)
            {
                AuthenticationTicket value;
                if(_cache.TryGetValue(key, out value))
                    return Task.FromResult(value);

                return Task.FromResult((AuthenticationTicket)null);
            }
        }

        public Task<string> StoreAsync(AuthenticationTicket ticket)
        {
            string key = Guid.NewGuid().ToString("N");
            lock (_lock)
            {
                _cache[key] = ticket;
            }

            return Task.FromResult(key);
        }
    }
}
