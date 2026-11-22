
using LibSodium;
using Cryptography.Crypto.Models;
using Cryptography.PKI.Interfaces;

namespace Cryptography.PKI
{
    public class PKIService : IPKIService
    {
        public KeyPair GenerateSigningKeyPair()
        {
            Span<byte> publicKey = stackalloc byte[CryptoSign.PublicKeyLen];
            var privateKey = new SecureMemory<byte>(CryptoSign.PrivateKeyLen);

            CryptoSign.GenerateKeyPair(publicKey, privateKey);
            privateKey.ProtectReadOnly();

            return new KeyPair(publicKey.ToArray(), privateKey);
        }
        public byte[] SignData(byte[] data, SecureMemory<byte> privateKey)
        {
            Span<byte> signature = stackalloc byte[CryptoSign.SignatureLen];
            CryptoSign.Sign(data, signature, privateKey);
            return signature.ToArray();
        }
        public bool VerifySignature(byte[] data, byte[] signature, byte[] publicKey)
        {
            try
            {
                return CryptoSign.Verify(data, signature, publicKey);
            }
            catch(LibSodiumException)
            {
                return false;
            }
        }
    }
}