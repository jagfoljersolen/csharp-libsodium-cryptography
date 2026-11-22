using Cryptography.Crypto;

ICryptoService cryptoService = new CryptoService();
string message = "Hello Bob symmetric!";

//KRYPTOGRAFIA SYMETRYCZNA
using var key = cryptoService.GenerateSymmetricKey();
var encryptedSymmetric = cryptoService.EncryptSymmetric(message,key);
var decryptedSymmetric = cryptoService.DecryptSymmetric(encryptedSymmetric, key);

Console.WriteLine("Tekst do zaszyfrowania: " + message);
Console.WriteLine("Zaszyfrowane dane (base64): " + Convert.ToBase64String(encryptedSymmetric));
Console.WriteLine("Odszyfrowane dane: " + decryptedSymmetric);

//KRYPTOGRAFIA ASYMETRYCZNA
message = "Hello Bob asymmetric!";

using var aliceKeys = cryptoService.GenerateAsymmetricKeyPair();
using var bobKeys = cryptoService.GenerateAsymmetricKeyPair();
var encryptedAsymmetric = cryptoService.EncryptAsymmetric(
    message, 
    bobKeys.PublicKey,
    aliceKeys.PrivateKey
    );
var decryptedAsymmetric = cryptoService.DecryptAsymmetric(
    encryptedAsymmetric, 
    aliceKeys.PublicKey, 
    bobKeys.PrivateKey
);

Console.WriteLine("Tekst do zaszyfrowania: " + message);
Console.WriteLine("Zaszyfrowane dane (base64): " + Convert.ToBase64String(encryptedAsymmetric));
Console.WriteLine("Odszyfrowane dane: " + decryptedAsymmetric);

// HYBRYDOWE SZYFROWANIE PLIKÓW
string filepath = "Crypto/Resources/dane.txt";
Console.WriteLine("Ścieżka pliku do zaszyfrowania: " + filepath);
var encryptedFilePath = cryptoService.EncryptFileSecretStream(filepath, bobKeys.PublicKey, aliceKeys.PrivateKey);
Console.WriteLine("Ścieżka zaszyfrowanego pliku: " + encryptedFilePath);
var decryptedFilePath = cryptoService.DecryptFileSecretStream(encryptedFilePath, aliceKeys.PublicKey, bobKeys.PrivateKey);
Console.WriteLine("Ścieżka odszyfrowanego pliku: " + decryptedFilePath);