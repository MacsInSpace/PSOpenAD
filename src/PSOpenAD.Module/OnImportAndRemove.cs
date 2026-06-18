using PSOpenAD.Native;
using System;
using System.Collections.Generic;
using System.Management.Automation;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Runtime.Loader;

namespace PSOpenAD.Module;

internal sealed class LibraryInfo : IDisposable
{
    public string Id { get; }
    public string Path { get; }
    public IntPtr Handle { get; }

    public LibraryInfo(string id, string path)
    {
        Id = id;
        Path = path;
        Handle = NativeLibrary.Load(path);
    }

    public void Dispose()
    {
        if (Handle != IntPtr.Zero)
            NativeLibrary.Free(Handle);
    }
    ~LibraryInfo() { Dispose(); }
}

internal sealed class NativeResolver : IDisposable
{
    private readonly Dictionary<string, LibraryInfo> NativeHandles = new();

    public NativeResolver()
    {
        AssemblyLoadContext.Default.ResolvingUnmanagedDll += ImportResolver;
    }

    public LibraryInfo? CacheLibrary(string id, string[] paths)
    {
        string? envOverride = Environment.GetEnvironmentVariable(id.ToUpperInvariant().Replace(".", "_"));
        if (!String.IsNullOrWhiteSpace(envOverride))
            paths = new[] { envOverride };

        foreach (string libPath in paths)
        {
            try
            {
                NativeHandles[id] = new LibraryInfo(id, libPath);
                return NativeHandles[id];
            }
            catch (DllNotFoundException) { }
        }

        return null;
    }

    private IntPtr ImportResolver(Assembly assembly, string libraryName)
    {
        if (NativeHandles.ContainsKey(libraryName))
            return NativeHandles[libraryName].Handle;

        return IntPtr.Zero;
    }

    public void Dispose()
    {
        foreach (KeyValuePair<string, LibraryInfo> native in NativeHandles)
            native.Value.Dispose();

        AssemblyLoadContext.Default.ResolvingUnmanagedDll -= ImportResolver;
        GC.SuppressFinalize(this);
    }
    ~NativeResolver() { Dispose(); }
}

public class OnModuleImportAndRemove : IModuleAssemblyInitializer, IModuleAssemblyCleanup
{
    internal const string MACOS_GSS_FRAMEWORK = "/System/Library/Frameworks/GSS.framework/GSS";

    internal NativeResolver? Resolver;

    public void OnImport()
    {
        Resolver = new NativeResolver();

        GlobalState state = GlobalState.GetFromTLS();

        // While channel binding isn't technically done by both these methods an Active Directory implementation
        // doesn't validate it's presence so from the purpose of a client it does work even if it's enforced on the
        // server end.
        state.Providers[AuthenticationMethod.Anonymous] = new(AuthenticationMethod.Anonymous, "ANONYMOUS",
            true, false, "");
        state.Providers[AuthenticationMethod.Simple] = new(AuthenticationMethod.Simple, "PLAIN", true,
            false, "");
        state.Providers[AuthenticationMethod.Certificate] = new(AuthenticationMethod.Certificate, "EXTERNAL",
            true, true, "");

        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            // Windows always has SSPI available.
            state.GssapiProvider = GssapiProvider.SSPI;
            state.Providers[AuthenticationMethod.Kerberos] = new(AuthenticationMethod.Kerberos, "GSSAPI",
                true, true, "");
            state.Providers[AuthenticationMethod.Negotiate] = new(AuthenticationMethod.Negotiate,
                "GSS-SPNEGO", true, true, "");

            // Default DC via DsGetDcName is deferred to DefaultDcDiscovery.Ensure (first implicit -Server).
        }
        else
        {
            state.GssapiProvider = GssapiProvider.None;
            LibraryInfo? gssapiLib = Resolver.CacheLibrary(GSSAPI.LIB_GSSAPI, new[] {
                MACOS_GSS_FRAMEWORK, // macOS GSS Framework (technically Heimdal)
                "libgssapi_krb5.so.2", // MIT krb5
                "libgssapi.so.3", "libgssapi.so", // Heimdal
            });
            _ = Resolver.CacheLibrary(Kerberos.LIB_KRB5, new[] {
                "/System/Library/PrivateFrameworks/Heimdal.framework/Heimdal", // macOS Heimdal Framework
                "libkrb5.so.3", // MIT krb5
                "libkrb5.so.26", "libkrb5.so", // Heimdal
            });

            if (gssapiLib == null)
            {
                state.Providers[AuthenticationMethod.Kerberos] = new(AuthenticationMethod.Kerberos,
                    "GSSAPI", false, false, "GSSAPI library not found");
                state.Providers[AuthenticationMethod.Negotiate] = new(AuthenticationMethod.Negotiate,
                    "GSS-SPNEGO", false, false, "GSSAPI library not found");

                state.DefaultDCError = "Failed to find GSSAPI library";
            }
            else
            {
                state.Providers[AuthenticationMethod.Kerberos] = new(AuthenticationMethod.Kerberos,
                    "GSSAPI", true, true, "");
                state.Providers[AuthenticationMethod.Negotiate] = new(AuthenticationMethod.Negotiate,
                    "GSS-SPNEGO", true, true, "");

                if (gssapiLib.Path == MACOS_GSS_FRAMEWORK)
                {
                    state.GssapiProvider = GssapiProvider.GSSFramework;
                }
                else if (NativeLibrary.TryGetExport(gssapiLib.Handle, "krb5_xfree", out var _))
                {
                    state.GssapiProvider = GssapiProvider.Heimdal;
                }
                else
                {
                    state.GssapiProvider = GssapiProvider.MIT;
                }

                // krb5 realm + LDAP SRV default-DC lookup deferred to DefaultDcDiscovery.Ensure.
            }
        }
    }

    public void OnRemove(PSModuleInfo module)
    {
        GlobalState state = GlobalState.GetFromTLS();
        foreach (OpenADSession session in state.Sessions)
            session.Close();

        state.Sessions = new();
        Resolver?.Dispose();
    }
}
