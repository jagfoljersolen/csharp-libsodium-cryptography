using System.Text;
using Cryptography.Crypto;
using Cryptography.PKI;
using Cryptography.PKI.Services;


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


// PODPISYWANIE I WERYFIKACJA DANYCH
var pkiService = new PKIService();

using var signerKeys = pkiService.GenerateSigningKeyPair();
using var otherKeys = pkiService.GenerateSigningKeyPair();

byte[] data = Encoding.UTF8.GetBytes("Wiadomość do podpisania");
byte[] signature = pkiService.SignData(data, signerKeys.PrivateKey);

bool ok = pkiService.VerifySignature(data, signature, signerKeys.PublicKey);
Console.WriteLine($"Poprawny podpis: {ok}");

byte[] temperedData = (byte[])data.Clone();
temperedData[0] ^= 0x01;
bool temperedDataResult = pkiService.VerifySignature(temperedData, signature, signerKeys.PublicKey);
Console.WriteLine($"Zmienione dane: {temperedDataResult}");

byte[] tamperedSignature = (byte[])signature.Clone();
tamperedSignature[0] ^= 0x01;
bool tamperedSigResult = pkiService.VerifySignature(data, tamperedSignature, signerKeys.PublicKey);
Console.WriteLine($"Zmieniony podpis: {tamperedSigResult}");

bool wrongKeyResult = pkiService.VerifySignature(data, signature, otherKeys.PublicKey);
Console.WriteLine($"Zły klucz publiczny: {wrongKeyResult}");


// Symulacja PKI
using var certificateAuthorityService = new CertificateAuthorityService(pkiService);

Console.WriteLine(certificateAuthorityService.RootCertificate.PrettyPrint());

var certificate = certificateAuthorityService.GenerateCertificate("Alice", aliceKeys.PublicKey);
Console.WriteLine("Issued Certificate:");
Console.WriteLine(certificate.PrettyPrint());
var valid = certificateAuthorityService.VerifyCertificate(certificate);
Console.WriteLine($"Czy podpis jest poprawny? {valid}");
aliceKeys.Dispose();

// LISTA UNIEWAŻNIEŃ (CRL)
var pkiService2 = new PKIService();
using var ca = new CertificateAuthorityService(pkiService2);

using var aliceCertKeys = pkiService2.GenerateSigningKeyPair();
using var bobCertKeys = pkiService2.GenerateSigningKeyPair();

var aliceCert = ca.GenerateCertificate("Alice", aliceCertKeys.PublicKey);
var bobCert = ca.GenerateCertificate("Bob", bobCertKeys.PublicKey);

Console.WriteLine($"Alice przed unieważnieniem: {ca.VerifyCertificate(aliceCert)}"); 
Console.WriteLine($"Bob przed unieważnieniem:   {ca.VerifyCertificate(bobCert)}");  

ca.RevokeCertificate(aliceCert.SerialNumber);
Console.WriteLine($"Czy Alice unieważniona:     {ca.IsRevoked(aliceCert.SerialNumber)}"); 

Console.WriteLine($"Alice po unieważnieniu:     {ca.VerifyCertificate(aliceCert)}"); 
Console.WriteLine($"Bob po unieważnieniu Alice: {ca.VerifyCertificate(bobCert)}");  