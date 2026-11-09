using System.Net.Security;
using FrpBan.Protocol.Security;
using Xunit;

namespace FrpBan.Tests.Security;

public class CertificateTrustTests
{
    [Fact]
    public void ExplicitAuthority_AcceptsItsValidServerCertificate()
    {
        using var authority = TestCertificates.CreateAuthority();
        using var leaf = TestCertificates.CreateLeaf(authority);
        Assert.True(CertificateTrust.Validate(leaf, null, SslPolicyErrors.RemoteCertificateChainErrors, authority, true));
    }

    [Fact]
    public void ExplicitAuthority_RejectsUnrelatedAuthority()
    {
        using var authority = TestCertificates.CreateAuthority();
        using var other = TestCertificates.CreateAuthority();
        using var leaf = TestCertificates.CreateLeaf(other);
        Assert.False(CertificateTrust.Validate(leaf, null, SslPolicyErrors.RemoteCertificateChainErrors, authority, true));
    }

    [Fact]
    public void ExplicitAuthority_DoesNotOverrideHostnameErrors()
    {
        using var authority = TestCertificates.CreateAuthority();
        using var leaf = TestCertificates.CreateLeaf(authority);
        Assert.False(CertificateTrust.Validate(leaf, null, SslPolicyErrors.RemoteCertificateNameMismatch, authority, true));
    }

    [Fact]
    public void ExplicitAuthority_RejectsExpiredCertificate()
    {
        using var authority = TestCertificates.CreateAuthority();
        using var leaf = TestCertificates.CreateLeaf(authority, expired: true);
        Assert.False(CertificateTrust.Validate(leaf, null, SslPolicyErrors.RemoteCertificateChainErrors, authority, true));
    }

    [Fact]
    public void MutualTls_RequiresClientAuthenticationUsage()
    {
        using var authority = TestCertificates.CreateAuthority();
        using var client = TestCertificates.CreateLeaf(authority, server: false);
        using var server = TestCertificates.CreateLeaf(authority);
        Assert.True(CertificateTrust.Validate(client, null, SslPolicyErrors.RemoteCertificateChainErrors, authority, false));
        Assert.False(CertificateTrust.Validate(server, null, SslPolicyErrors.RemoteCertificateChainErrors, authority, false));
    }
}
