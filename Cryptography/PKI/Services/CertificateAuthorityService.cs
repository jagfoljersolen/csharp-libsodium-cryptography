using Cryptography.Crypto.Models;
using Cryptography.PKI.Interfaces;
using Cryptography.PKI.Models;
using System.Text;
using System.Text.Json;
namespace Cryptography.PKI.Services
{
    public class CertificateAuthorityService : ICertificateAuthorityService
    {
        private readonly IPKIService _pkiService;
        private readonly KeyPair _keyPair;
        private readonly HashSet<string> _revokedSerialNumbers = new();
        private readonly X509Certificate _rootCertificate;
        public X509Certificate RootCertificate => _rootCertificate;
        public CertificateAuthorityService(IPKIService pkiService)
        {
            _pkiService = pkiService;
            _keyPair = _pkiService.GenerateSigningKeyPair();
            _rootCertificate = GenerateRootCertificate();
        }
        public byte[] GetPublicKey() => _keyPair.PublicKey;
        private X509Certificate GenerateRootCertificate()
        {
            var cert = new X509Certificate
            {
                SerialNumber = Guid.NewGuid().ToString(),
                Subject = "RootCA",
                Issuer = "RootCA",
                ValidFrom = DateTime.UtcNow,
                ValidTo = DateTime.UtcNow.AddYears(10),
                SignatureAlgorithm = "Ed25519",
                PublicKey = _keyPair.PublicKey
            };
            var dataToSign = cert.ComputeCertificateDigest();
            cert.Signature = _pkiService.SignData(dataToSign, _keyPair.PrivateKey);
            return cert;
        }
        public X509Certificate GenerateCertificate(string subject, byte[] publicKey)
        {
            var cert = new X509Certificate
            {
                SerialNumber = Guid.NewGuid().ToString(),
                Subject = subject,
                Issuer = RootCertificate.Subject,
                ValidFrom = DateTime.UtcNow,
                ValidTo = DateTime.UtcNow.AddDays(30),
                SignatureAlgorithm = "Ed25519",
                PublicKey = publicKey
            };
            var dataToSign = cert.ComputeCertificateDigest();
            cert.Signature = _pkiService.SignData(dataToSign, _keyPair.PrivateKey);
            return cert;
        }
        private static bool IsWithinValidityPeriod(X509Certificate cert)
        {
            var now = DateTime.UtcNow;
            return now >= cert.ValidFrom && now <= cert.ValidTo;
        }

        public void RevokeCertificate(string serialNumber)
        {
            _revokedSerialNumbers.Add(serialNumber);
        }

        public bool IsRevoked(string serialNumber)
        {
            return _revokedSerialNumbers.Contains(serialNumber);
        }
        public bool VerifyCertificate(X509Certificate cert)
        {
            if (IsRevoked(cert.SerialNumber))
                return false;

            if (!IsWithinValidityPeriod(cert))
                return false;
                
            var dataToVerify = cert.ComputeCertificateDigest();
        
            return _pkiService.VerifySignature(dataToVerify, cert.Signature, _keyPair.PublicKey);
        }

        public void Dispose()
        {
            _keyPair?.Dispose();
        }

        public void ExportToPem(X509Certificate cert, String path)
        {
            string json = JsonSerializer.Serialize(cert);
            string base64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(json));

            var sb = new StringBuilder();
            sb.AppendLine("-----BEGIN CERTIFICATE-----");
            int lineLength = 64;
            for (int i=0; i<base64.Length; i+=lineLength)
            {
                sb.AppendLine(base64.Substring(i, Math.Min(lineLength, base64.Length - i)));
            }
            sb.Append("-----END CERTIFICATE-----");

            File.WriteAllText(path, sb.ToString());

        }

        public X509Certificate ImportFromPem(string path) 
        {
            string[] lines = File.ReadAllLines(path);

            int start = Array.FindIndex(lines, l => l.Trim() == "-----BEGIN CERTIFICATE-----");
            int end = Array.FindIndex(lines, l => l.Trim() == "-----END CERTIFICATE-----");

            if (start < 0 || end < 0 || end <= start)
                throw new FormatException("Nieprawidłowy format PEM: brak nagłówków.");

            string base64 = string.Concat(lines[(start + 1)..end].Select(l => l.Trim()));

            byte[] jsonBytes = Convert.FromBase64String(base64);
            string json = Encoding.UTF8.GetString(jsonBytes);

            return JsonSerializer.Deserialize<X509Certificate>(json)
                ?? throw new FormatException("Nie udało się zdeserializować certyfikatu.");

        }
    }
}