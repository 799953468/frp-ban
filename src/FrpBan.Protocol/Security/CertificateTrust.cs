using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace FrpBan.Protocol.Security;

/// <summary>Validates TLS peers against an explicit CA without bypassing names or validity dates.</summary>
public static class CertificateTrust
{
    /// <summary>Checks the peer certificate, preserving TLS hostname validation for servers.</summary>
    /// <param name="certificate">The peer certificate.</param>
    /// <param name="peerChain">Intermediate certificates supplied by TLS.</param>
    /// <param name="errors">Errors detected by the TLS stack.</param>
    /// <param name="authority">The exclusive trust anchor, or null for system trust.</param>
    /// <param name="serverCertificate">True to require server authentication; false for client authentication.</param>
    /// <returns>True only when the peer satisfies the configured trust policy.</returns>
    public static bool Validate(X509Certificate? certificate, X509Chain? peerChain,
        SslPolicyErrors errors, X509Certificate2? authority, bool serverCertificate)
    {
        if (certificate is null || (errors & ~SslPolicyErrors.RemoteCertificateChainErrors) != 0)
            return false;
        if (authority is null)
            return errors == SslPolicyErrors.None;

        using var leaf = X509CertificateLoader.LoadCertificate(certificate.GetRawCertData());
        using var chain = new X509Chain();
        chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        chain.ChainPolicy.CustomTrustStore.Add(authority);
        chain.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag;
        // Custom PKI deployments may be offline; do not download AIA/CRL URLs from peers.
        chain.ChainPolicy.DisableCertificateDownloads = true;
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        chain.ChainPolicy.ApplicationPolicy.Add(new Oid(serverCertificate
            ? "1.3.6.1.5.5.7.3.1" : "1.3.6.1.5.5.7.3.2"));
        if (peerChain is not null)
            foreach (var element in peerChain.ChainElements)
                chain.ChainPolicy.ExtraStore.Add(element.Certificate);
        return chain.Build(leaf);
    }
}
