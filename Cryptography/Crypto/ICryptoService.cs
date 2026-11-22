using Cryptography.Crypto.Models;
using LibSodium;

namespace Cryptography.Crypto
{
    public interface ICryptoService
    {
        SecureMemory<byte> GenerateSymmetricKey();
        byte[] EncryptSymmetricBytes(byte [] data, SecureMemory<byte> key);
        byte[] DecryptSymmetricBytes(byte[] ciphertext, SecureMemory<byte> key);
        byte[] EncryptSymmetric(string plaintext, SecureMemory<byte> key);
        string DecryptSymmetric(byte[] ciphertext, SecureMemory<byte> key);


        KeyPair GenerateAsymmetricKeyPair();
        byte[] EncryptAsymmetricBytes(byte[] data, byte[] recipientPublicKey, SecureMemory<byte> senderPrivateKey);
        byte[] DecryptAsymmetricBytes(byte[] ciphertext, byte[] senderPublicKey, SecureMemory<byte> recipientPrivateKey);
        byte[] EncryptAsymmetric(string plaintext, byte[] recipientPublicKey, SecureMemory<byte> senderPrivateKey);
        string DecryptAsymmetric(byte[] ciphertext, byte[] senderPublicKey, SecureMemory<byte> recipientPrivateKey);

        string EncryptFileSecretStream(string filepath, byte[] recipientPublicKey, SecureMemory<byte> senderPrivateKey);
        string DecryptFileSecretStream(string filepath, byte[] senderPublicKey, SecureMemory<byte> recipientPrivateKey);


    }
}

