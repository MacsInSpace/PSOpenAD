using DnsClient;
using PSOpenAD.Native;
using System;
using System.ComponentModel;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;

namespace PSOpenAD.Module;

/// <summary>
/// Lazy default domain-controller discovery (Windows DsGetDcName / Unix SRV via krb5 realm).
/// Deferred out of <see cref="OnModuleImportAndRemove.OnImport"/> so Import-Module is not blocked
/// on DNS when the OS resolver cannot reach AD SRV records (common on VPN).
/// </summary>
internal static class DefaultDcDiscovery
{
    private static LookupClient CreateLookupClient()
    {
        string? servers = Environment.GetEnvironmentVariable("PSOPENAD_DNS_SERVERS");
        if (string.IsNullOrWhiteSpace(servers))
        {
            return new LookupClient();
        }

        IPAddress[] addrs = servers
            .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Select(static s => IPAddress.Parse(s))
            .ToArray();
        return new LookupClient(addrs);
    }

    internal static void Ensure(GlobalState state)
    {
        if (state.DefaultDcDiscoveryAttempted)
        {
            return;
        }

        lock (state.DefaultDcDiscoveryLock)
        {
            if (state.DefaultDcDiscoveryAttempted)
            {
                return;
            }

            try
            {
                if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                {
                    DiscoverWindowsDefaultDc(state);
                }
                else
                {
                    DiscoverUnixDefaultDc(state);
                }
            }
            finally
            {
                state.DefaultDcDiscoveryAttempted = true;
            }
        }
    }

    private static void DiscoverWindowsDefaultDc(GlobalState state)
    {
        const GetDcFlags getDcFlags = GetDcFlags.DS_IS_DNS_NAME | GetDcFlags.DS_ONLY_LDAP_NEEDED |
            GetDcFlags.DS_RETURN_DNS_NAME | GetDcFlags.DS_WRITABLE_REQUIRED;
        string? dcName = null;
        try
        {
            DCInfo dcInfo = NetApi32.DsGetDcName(null, null, null, getDcFlags, null);
            dcName = dcInfo.Name?.TrimStart('\\');
        }
        catch (Win32Exception e) when (e.NativeErrorCode == 1355) // ERROR_NO_SUCH_DOMAIN
        {
            // Non-domain-joined hosts may still use explicit -Server.
        }
        catch (Exception e)
        {
            state.DefaultDCError = $"Failure calling DsGetDcName to get default DC: {e.Message}";
        }

        if (!string.IsNullOrWhiteSpace(dcName))
        {
            state.DefaultDC = new Uri($"ldap://{dcName}:389/");
        }
        else if (string.IsNullOrEmpty(state.DefaultDCError))
        {
            state.DefaultDCError = "No configured default DC on host";
        }
    }

    private static void DiscoverUnixDefaultDc(GlobalState state)
    {
        if (state.GssapiProvider == GssapiProvider.None)
        {
            if (string.IsNullOrEmpty(state.DefaultDCError))
            {
                state.DefaultDCError = "Failed to find GSSAPI library";
            }
            return;
        }

        if (!TryGetDefaultKerberosRealm(out var defaultRealm, out var realmException))
        {
            state.DefaultDCError = $"Failed to lookup krb5 default realm: {realmException}";
            return;
        }

        string baseDomain = $"dc._msdcs.{defaultRealm}";
        LookupClient dnsLookup = CreateLookupClient();
        try
        {
            ServiceHostEntry[] res = dnsLookup.ResolveService(baseDomain, "ldap", ProtocolType.Tcp);

            ServiceHostEntry? first = res.OrderBy(r => r.Priority).ThenBy(r => r.Weight).FirstOrDefault();
            if (first != null)
            {
                state.DefaultDC = new Uri($"ldap://{first.HostName}:{first.Port}/");
            }
            else
            {
                state.DefaultDCError = $"No SRV records for _ldap._tcp.{baseDomain} found";
            }
        }
        catch (DnsResponseException e)
        {
            state.DefaultDCError = $"DNS Error looking up SRV records for _ldap._tcp.{baseDomain}: {e.Message}";
        }
        catch (Exception e)
        {
            state.DefaultDCError =
                $"Unknown error looking up SRV records for _ldap._tcp.{baseDomain}: {e.GetType().Name} - {e.Message}";
        }
    }

    private static bool TryGetDefaultKerberosRealm(
        [NotNullWhen(true)] out string? realm,
        [NotNullWhen(false)] out string? errorMessage)
    {
        realm = null;
        errorMessage = null;

        using var ctx = Kerberos.InitContext();
        if (Kerberos.TryGetDefaultRealm(ctx, out realm, out var defaultRealmException))
        {
            return true;
        }

        if (!Kerberos.TryGetDefaultCCache(ctx, out var ccache, out var defaultCCException))
        {
            errorMessage = $"{defaultRealmException.Message}, {defaultCCException.Message}";
            return false;
        }
        using (ccache)
        {
            if (!Kerberos.TryGetCCachePrincipal(ctx, ccache, out var principal, out var defaultCCPrincipalException))
            {
                errorMessage = $"{defaultRealmException.Message}, {defaultCCPrincipalException.Message}";
                return false;
            }

            using (principal)
            {
                if (Kerberos.TryUnparseName(ctx, principal, out var principalName, out var defaultUnparseException))
                {
                    int realmIdx = principalName.IndexOf('@');
                    if (realmIdx != -1)
                    {
                        realm = principalName[(realmIdx + 1)..];
                        return true;
                    }

                    errorMessage =
                        $"{defaultRealmException.Message}, failed to find principal realm in name '{principalName}'";
                    return false;
                }

                errorMessage = $"{defaultRealmException.Message}, {defaultUnparseException.Message}";
                return false;
            }
        }
    }
}
