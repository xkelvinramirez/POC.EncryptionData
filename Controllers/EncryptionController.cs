using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using POC.EncryptionData.Common;
using System.Security.Cryptography;


namespace POC.EncryptionData.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class EncryptionController : ControllerBase
    {
        (string publicKey, string privateKey) _keysRsa = RsaEncryptionManager.GenerateKeys();
        (string publicKey, string privateKey) _keysEcc = EccEncryptionManager.GenerateKeysECC();

        [HttpGet]
        [Route("algoritm/aes")]

        public async Task<string> AES(string plaintext)
        {

            byte[] key = new byte[32]; // 256-bit key
            byte[] iv = new byte[16]; // 128-bit IV
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(key);
                rng.GetBytes(iv);
            }
            // Encrypt
            byte[] ciphertext = AesEncryptionManager.Encrypt(plaintext, key, iv);
            string encryptedText = Convert.ToBase64String(ciphertext);

            // Decrypt
            byte[] bytes = Convert.FromBase64String(encryptedText);
            string decryptedText = AesEncryptionManager.Decrypt(bytes, key, iv);

            return $"Encrypted Text: {encryptedText} -  Decrypted Text: {decryptedText}";
        }


        [HttpGet]
        [Route("algoritm/rsa")]

        public async Task<string> Rsa(string strValue)
        {
            var encryptedText = RsaEncryptionManager.EncryptRSA(_keysRsa.publicKey, strValue);
            var decryptedText = RsaEncryptionManager.DecryptRSA(_keysRsa.privateKey, encryptedText);

            return $"Encrypted Text: {encryptedText} -  Decrypted Text: {decryptedText}";
        }



        [HttpGet]
        [Route("algoritm/ecc")]

        public async Task<string> Ecc(string strValue)
        {

            var signature = EccEncryptionManager.SignECC(_keysEcc.privateKey, strValue);
            var respVerify = EccEncryptionManager.VerifyECC(_keysEcc.publicKey, strValue, signature);

            return $"Signature: {signature} - Verify : {respVerify} ";

        }

    }
}