using Cryptography.Crypto.Models;
using Libsodium;

namespace Cryptography.PKI.interfaces
{
    public interface IPKIService
    {
        KeyValuePair GenerateSigningKeyPair();
        byte[] SignData(byte[] data, SecureMemory<byte> privateKey);
        bool VerifySignature(byte[] data, byte[] signature, byte[] publicKey);
    }
}