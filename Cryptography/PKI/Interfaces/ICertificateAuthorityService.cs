using Cryptography.PKI.Models;

namespace Cryptography.PKI.Interfaces
{
    public interface ICertificateAuthorityService : IDisposable
    {
        X509Certificate RootCertificate { get; }

        byte[] GetPublicKey();
        X509Certificate GenerateCertificate(string subject, byte[] publicKey);
        bool VerifyCertificate(X509Certificate cert);
        void ExportToPem(X509Certificate cert, String path);
        X509Certificate ImportFromPem(string path);

        void RevokeCertificate(string serialNumber);
        bool IsRevoked(string serialNumber);

    }
}
