using System.Security.Cryptography;
using System.Text;

namespace POC.EncryptionData.Common
{
    public static class RsaEncryptionManager
    {
        public static (string publicKey, string privateKey) GenerateKeys()
        {
            using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
            {
                string publicKey = rsa.ToXmlString(false);
                string privateKey = rsa.ToXmlString(true);
                return (publicKey, privateKey);
            }
        }

        public static async Task<string> EncryptRSA(string publicKey, string plainText)
        {
            var taskEncrypt = Task.Run(() =>
            {
                using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
                {
                    rsa.FromXmlString(publicKey);
                    byte[] plainBytes = Encoding.UTF8.GetBytes(plainText);
                    byte[] encryptedBytes = rsa.Encrypt(plainBytes, false);
                    return Convert.ToBase64String(encryptedBytes);
                }
            });
            return await taskEncrypt;
        }

        public static async Task<string> DecryptRSA(string privateKey, string cipherText)
        {
            var taskDecrypt = Task.Run(() =>
            {
                using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
                {
                    rsa.FromXmlString(privateKey);
                    byte[] encryptedBytes = Convert.FromBase64String(cipherText);
                    byte[] decryptedBytes = rsa.Decrypt(encryptedBytes, false);
                    return Encoding.UTF8.GetString(decryptedBytes);
                }
            });
            return await taskDecrypt;
        }
    }
}
