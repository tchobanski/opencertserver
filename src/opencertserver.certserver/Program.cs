using System.Runtime.CompilerServices;

[assembly: InternalsVisibleTo("opencertserver.certserver.tests")]

namespace OpenCertServer.CertServer;

using System.Security.Cryptography;
using OpenCertServer.Ca.Utils.Ca;
using OpenCertServer.Est.Server.Handlers;
using System.Linq;
using System.Numerics;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using Acme.Abstractions.IssuanceServices;
using Est.Server;
using Est.Server.BasicAuthentication;
using Microsoft.AspNetCore.Authentication.Certificate;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.Server.Kestrel.Https;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Acme.Server;
using Acme.Server.Extensions;
using Ca;
using Ca.Server;
using Contrib.Intune;
using Scep.Server;

internal static class Program
{
    public static async Task Main(string[] args)
    {
        if (args.Length == 0)
        {
            throw new Exception("No configuration values passed");
        }

        var builder = WebApplication.CreateBuilder(args);
        builder.Configuration.AddEnvironmentVariables().AddCommandLine(args)
            .AddJsonFile("appsettings.json", true, true);
        var services = builder.Services
            .AddCors(options =>
            {
                options.AddPolicy("TrustedClients", pb =>
                {
                    pb
                        .WithOrigins(
                            builder
                                .Configuration.GetSection("Cors:TrustedOrigins")
                                .GetChildren()
                                .Select(origin => origin.Value)
                                .OfType<string>()
                                .ToArray())
                        .AllowCredentials()
                        .AllowAnyHeader()
                        .AllowAnyMethod();
                });
            })
            .AddInMemoryCertificateStore();
        var port = int.TryParse(builder.Configuration.GetSection("port").Value, out var p)
            ? p
            : 5001; //portIndex >= 0 ? int.Parse(args[portIndex + 1]) : 5001;
        var index = 0;
        List<string> ocspUrls = [];
        List<string> caIssuerUrls = [];
        List<string> crlUrls = [];
        while (index >= 0)
        {
            index = Array.IndexOf(args, "--ocsp", index);
            if (index < 0)
            {
                continue;
            }

            ocspUrls.Add(args[index + 1]);
            index++;
        }

        if (ocspUrls.Count == 0)
        {
            // The development default. It used to be the first entry whatever --ocsp said, so every
            // issued certificate pointed relying parties at localhost:6001 before the real responder.
            ocspUrls.Add("http://localhost:6001/ocsp");
        }

        index = 0;
        while (index >= 0)
        {
            index = Array.IndexOf(args, "--ca-issuer", index);
            if (index < 0)
            {
                continue;
            }

            caIssuerUrls.Add(args[index + 1]);
            index++;
        }

        index = 0;
        while (index >= 0)
        {
            index = Array.IndexOf(args, "--crl", index);
            if (index < 0)
            {
                continue;
            }

            if (index + 1 < args.Length)
            {
                crlUrls.Add(args[index + 1]);
            }

            index++;
        }

        var dn = builder.Configuration.GetSection("dn");
        if (dn.Value is not null)
        {
            services = services.AddSelfSignedCertificateAuthority(
                    new X500DistinguishedName(
                        dn.Value.StartsWith("CN=") ? dn.Value : $"CN={dn.Value}"),
                    ocspUrls.ToArray(),
                    crlUrls.ToArray(),
                    caIssuerUrls.ToArray(),
                    TimeSpan.FromDays(90))
                .AddEstServer<CsrTemplateLoader>();
        }
        else
        {
            var rsaProfile = await CreateProfile(
                args,
                builder.Configuration,
                profileName: "rsa",
                certArgument: "--rsa",
                keyArgument: "--rsa-key",
                publishedArgument: "--rsa-published",
                getPrivateKey: cert => cert.GetRSAPrivateKey()).ConfigureAwait(false);
            var ecdsaProfile = await CreateProfile(
                args,
                builder.Configuration,
                profileName: "ecdsa",
                certArgument: "--ec",
                keyArgument: "--ec-key",
                publishedArgument: "--ec-published",
                getPrivateKey: cert => cert.GetECDsaPrivateKey()).ConfigureAwait(false);
            services = services
                .AddCertificateAuthority(
                    new CaConfiguration(
                        new CaProfileSet("rsa", rsaProfile, ecdsaProfile),
                        ocspUrls.ToArray(),
                        crlUrls.ToArray(),
                        caIssuerUrls.ToArray()))
                .AddEstServer<CsrTemplateLoader>();
        }

        services = await AddScep(services, args, builder.Configuration).ConfigureAwait(false);

        var a = Array.IndexOf(args, "--authority");
        var authority = a >= 0
            ? args[a + 1]
            : throw new Exception("No authority specified. Use --authority <url> to specify the authority URL.");

        var aud = Array.IndexOf(args, "--audience");
        var audiences = aud >= 0
            ? args[aud + 1].Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            : throw new Exception("No audience specified. Use --audience <url> to specify the audience URL.");

        var forwardedHeadersOptions = CreateForwardedHeaderOptions();

        _ = services.AddAuthentication()
            .AddJwtBearer()
            .AddCertificate()
            // User name and password for EST (RFC 7030 §3.2.3): off until Est:BasicAuth:Users or
            // Est:BasicAuth:UsersFile is set. Hashes only - `opencert hash-password` makes them.
            .AddEstBasicAuthentication(options => ReadBasicAuthentication(builder.Configuration, options))
            .AddCertificateCache(options =>
            {
                options.CacheSize = 1024;
                options.CacheEntryExpiration = TimeSpan.FromMinutes(5);
            })
            .Services
            .AddAcmeServer(builder.Configuration)
            .AddAcmeInMemoryStore()
            .AddSingleton(new JwtParameters { Authority = authority, Audiences = audiences })
            .AddSingleton<ICsrValidator, DefaultCsrValidator>()
            .AddSingleton<IIssueCertificates, DefaultIssuer>()
            .ConfigureOptions<ConfigureJwtBearerOptions>()
            .ConfigureOptions<ConfigureCertificateAuthenticationOptions>()
            .AddAuthorization(options => options.AddPolicy(
                ContribIntuneExtensions.SyncPolicyName,
                policy => policy.RequireAuthenticatedUser().RequireRole(RevocationAuthorizationConstants.CaAdminRole)))
            .AddCertificateAuthorityAuthorization()
            .AddHealthChecks();
        builder.WebHost.UseKestrel(options =>
            {
                options.AddServerHeader = false;
                options.ConfigureHttpsDefaults(httpsOptions =>
                {
                    // RFC 7030 requires TLS 1.1 or later for EST; prefer TLS 1.2+ in practice.
                    httpsOptions.SslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13;
                    // Kestrel presents an X.509 server certificate that is expected to conform to RFC5280.
                    // Leave TLS session resumption enabled (the default) because RFC 7030 recommends session resumption support.
                    // Ask the client for a certificate: EST re-enrollment and self-service revocation
                    // authenticate with one. Kestrel only transports it; the certificate authentication
                    // handler validates it against the CA's own certificates.
                    httpsOptions.ClientCertificateMode = ClientCertificateMode.AllowCertificate;
                    httpsOptions.AllowAnyClientCertificate();
                });
            })
            .UseUrls($"https://*:{port}");
        var app = builder.Build();
        app.UseHttpsRedirection()
            .UseCors("TrustedClients")
            .UseForwardedHeaders(forwardedHeadersOptions)
            .UseHealthChecks("/health")
            .UseCertificateForwarding()
            .UseRouting()
            .UseAuthentication()
            .UseAuthorization()
            .UseAcmeServer()
            .UseEstServer(
                enrollPolicy: EstPolicy(),
                reEnrollPolicy: EstPolicy(),
                serverKeyGenPolicy: EstPolicy())
            .UseCertificateAuthorityServer();
        app.MapScepServer();
        if (builder.Configuration.GetSection(IntuneOptions.SectionName).Exists())
        {
            app.MapIntuneSync();
        }

        await app.RunAsync().ConfigureAwait(false);
    }

    /// <summary>
    /// Est:BasicAuth from configuration, read by hand - the project is built for AOT, and binding a
    /// typed object needs code generated at run time.
    /// </summary>
    private static void ReadBasicAuthentication(IConfiguration configuration, EstBasicAuthenticationOptions options)
    {
        var section = configuration.GetSection("Est:BasicAuth");
        options.UsersFile = section["UsersFile"];
        options.Realm = section["Realm"] ?? options.Realm;
        foreach (var user in section.GetSection("Users").GetChildren())
        {
            if (!string.IsNullOrWhiteSpace(user.Value))
            {
                options.Users[user.Key] = user.Value;
            }
        }
    }

    /// <summary>
    /// Who may enroll: a token, a client certificate, or - where users are configured - a user name and
    /// password. The Basic scheme is always registered, so listing it costs nothing when it is off.
    /// </summary>
    private static AuthorizationPolicy EstPolicy()
    {
        return new AuthorizationPolicyBuilder()
            .AddAuthenticationSchemes(
                JwtBearerDefaults.AuthenticationScheme,
                CertificateAuthenticationDefaults.AuthenticationScheme,
                EstBasicAuthenticationDefaults.AuthenticationScheme)
            .RequireAuthenticatedUser()
            .Build();
    }

    /// <summary>
    /// Wires SCEP like EST and ACME. GetCACaps and GetCACert only publish public information;
    /// PKIOperation issues nothing until a challenge is configured (<c>Scep:Challenge</c>,
    /// e.g. the environment variable <c>Scep__Challenge</c> - not a command line argument,
    /// where it would show in the process list).
    /// </summary>
    private static async Task<IServiceCollection> AddScep(
        IServiceCollection services,
        string[] args,
        IConfiguration configuration)
    {
        // The RA decrypts requests and signs responses; SCEP defines the envelope for RSA
        // key transport only, so the RA is RSA even for an ECDSA CA.
        var raCertificate = GetArgumentValue(args, "--scep-ra") is not null
            ? await CreateCert(args, "--scep-ra", "--scep-ra-key").ConfigureAwait(false)
            : CreateTransientRaCertificate();
        if (raCertificate.GetRSAPrivateKey() is null)
        {
            throw new InvalidOperationException("The SCEP RA certificate (--scep-ra) needs an RSA private key.");
        }

        var options = new ScepServerOptions
        {
            RaCertificate = raCertificate,
            DefaultProfile = configuration["Scep:DefaultProfile"]
        };
        // Intune takes precedence over a shared secret: with <c>Scep:Intune</c> configured,
        // every request is validated by Intune's SCEP validation service, and the revocation
        // sync is mapped (see opencertserver.contrib.intune).
        if (configuration.GetSection(IntuneOptions.SectionName).Exists())
        {
            return services.AddIntune(configuration).AddScepServer(options);
        }

        var challenge = configuration["Scep:Challenge"];
        return string.IsNullOrEmpty(challenge)
            ? services.AddScepServer(options)
            : services.AddScepServer(options, new SharedSecretChallengeValidator(challenge));
    }

    /// <summary>
    /// Without a configured RA, a self-signed one is created at start-up. It changes with
    /// every restart, which SCEP clients tolerate because they fetch GetCACert before each
    /// enrollment; a deployment that pins the RA configures <c>--scep-ra</c>.
    /// </summary>
    private static X509Certificate2 CreateTransientRaCertificate()
    {
        using var key = RSA.Create(2048);
        var request = new CertificateRequest("CN=OpenCertServer SCEP RA", key, HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509KeyUsageExtension(
            X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment, true));
        using var certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5),
            DateTimeOffset.UtcNow.AddYears(1));
        // Round-trip through PKCS#12 so the key outlives the RSA instance above on every platform.
        return X509CertificateLoader.LoadPkcs12(certificate.Export(X509ContentType.Pkcs12), null);
    }

    private static ForwardedHeadersOptions CreateForwardedHeaderOptions()
    {
        var forwardedHeadersOptions = new ForwardedHeadersOptions
        {
            ForwardedHeaders = ForwardedHeaders.All,
            ForwardLimit = null,
            AllowedHosts = []
        };
        forwardedHeadersOptions.KnownIPNetworks.Clear();
        forwardedHeadersOptions.KnownProxies.Clear();

        return forwardedHeadersOptions;
    }

    private static async Task<CaProfile> CreateProfile(
        string[] args,
        IConfiguration configuration,
        string profileName,
        string certArgument,
        string keyArgument,
        string publishedArgument,
        Func<X509Certificate2, AsymmetricAlgorithm?> getPrivateKey)
    {
        var certificate = await CreateCert(args, certArgument, keyArgument).ConfigureAwait(false);
        var privateKey = getPrivateKey(certificate)
         ?? throw new InvalidOperationException(
                $"The certificate configured for profile '{profileName}' does not expose a compatible private key.");
        var activeCertificate = X509Certificate2.CreateFromPem(certificate.ExportCertificatePem());
        var publishedCertificatePath =
            GetArgumentValue(args, publishedArgument) ?? configuration[$"{profileName}:PublishedPem"];

        return new CaProfile
        {
            Name = profileName,
            CertificateChain = [activeCertificate],
            PublishedCertificateChain = await LoadPublishedCertificateChain(publishedCertificatePath, activeCertificate)
                .ConfigureAwait(false),
            CertificateValidity = TimeSpan.FromDays(90),
            CrlNumber = BigInteger.Zero,
            PrivateKey = privateKey,
            CertificatePolicies = ReadList(configuration, $"{profileName}:CertificatePolicies") ?? [],
            KeyUsage = ReadKeyUsage(configuration[$"{profileName}:KeyUsage"]),
            ExtendedKeyUsages = ReadList(configuration, $"{profileName}:ExtendedKeyUsages")
        };
    }

    /// <summary>
    /// Reads a list from configuration, either as an array section (<c>rsa:CertificatePolicies:0</c>,
    /// <c>rsa__CertificatePolicies__0</c> in the environment) or as one value with the entries
    /// separated by commas, semicolons or whitespace. Null when the key is absent, so a profile
    /// property that distinguishes "not set" from "empty" keeps that distinction.
    /// </summary>
    private static IReadOnlyList<string>? ReadList(IConfiguration configuration, string key)
    {
        var section = configuration.GetSection(key);
        var children = section.GetChildren().Select(c => c.Value).OfType<string>().ToArray();
        if (children.Length > 0)
        {
            return children;
        }

        return section.Value is { } value
            ? value.Split([',', ';', ' ', '\t', '\n'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            : null;
    }

    /// <summary>
    /// Reads key usage flags by name, several separated by commas (<c>DigitalSignature, KeyEncipherment</c>).
    /// </summary>
    private static X509KeyUsageFlags? ReadKeyUsage(string? value)
    {
        return string.IsNullOrWhiteSpace(value)
            ? null
            : Enum.Parse<X509KeyUsageFlags>(value, ignoreCase: true);
    }

    private static string? GetArgumentValue(string[] args, string argumentName)
    {
        var index = Array.IndexOf(args, argumentName);
        return index >= 0 && index + 1 < args.Length
            ? args[index + 1]
            : null;
    }

    private static async Task<X509Certificate2Collection> LoadPublishedCertificateChain(
        string? certificateBundlePath,
        X509Certificate2 activeCertificate)
    {
        if (string.IsNullOrWhiteSpace(certificateBundlePath))
        {
            return [];
        }

        var pem = await File.ReadAllTextAsync(certificateBundlePath).ConfigureAwait(false);
        X509Certificate2Collection importedCertificates = [];
        importedCertificates.ImportFromPem(pem);
        if (importedCertificates.Count == 0)
        {
            throw new InvalidOperationException(
                $"The published EST certificate bundle '{certificateBundlePath}' did not contain any PEM certificates.");
        }

        X509Certificate2Collection publishedCertificates = [];
        AddUniqueCertificate(publishedCertificates,
            X509Certificate2.CreateFromPem(activeCertificate.ExportCertificatePem()));
        foreach (var certificate in importedCertificates)
        {
            AddUniqueCertificate(publishedCertificates, certificate);
        }

        return publishedCertificates;
    }

    private static void AddUniqueCertificate(
        X509Certificate2Collection collection,
        X509Certificate2 certificate)
    {
        if (collection.Any(existing =>
            string.Equals(existing.Thumbprint, certificate.Thumbprint, StringComparison.OrdinalIgnoreCase)))
        {
            certificate.Dispose();
            return;
        }

        collection.Add(certificate);
    }

    private static async Task<X509Certificate2> CreateCert(string[] args, string cert, string certKey)
    {
        var certIndex = args[Array.IndexOf(args, cert) + 1];
        var keyIndex = Array.IndexOf(args, certKey);
        var key = keyIndex >= 0 ? args[keyIndex + 1] : null;
        using var file = File.OpenText(certIndex);
        using var keyFile = key == null ? TextReader.Null : File.OpenText(key);
        var pem = await file.ReadToEndAsync().ConfigureAwait(false);
        var keyPem = await keyFile.ReadToEndAsync().ConfigureAwait(false);
        var x509 = key == null
            ? X509Certificate2.CreateFromPem(pem)
            : X509Certificate2.CreateFromPem(pem, keyPem);
        return x509;
    }
}
