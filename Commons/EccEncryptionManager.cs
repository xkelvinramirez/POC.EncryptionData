using System.Security.Cryptography;
using System.Text;

namespace POC.EncryptionData.Common
{
    public static class EccEncryptionManager
    {
        public static (string publicKey, string privateKey) GenerateKeysECC()
        {
            using (ECDsaCng ecc = new ECDsaCng())
            {
                string publicKey = Convert.ToBase64String(ecc.ExportSubjectPublicKeyInfo());
                string privateKey = Convert.ToBase64String(ecc.ExportECPrivateKey());
                return (publicKey, privateKey);
            }
        }

        public static async Task<string> SignECC(string privateKey, string data)
        {
            var taskEncrypt = Task.Run(() =>
            {
                using (ECDsaCng ecc = new ECDsaCng())
                {
                    ecc.ImportECPrivateKey(Convert.FromBase64String(privateKey), out _);
                    byte[] dataBytes = Encoding.UTF8.GetBytes(data);
                    byte[] signature = ecc.SignData(dataBytes);
                    return Convert.ToBase64String(signature);
                }
            });
            return await taskEncrypt;
        }

        public static async Task<bool> VerifyECC(string publicKey, string data, string signature)
        {
            var taskDecrypt = Task.Run(() =>
            {
                using (ECDsaCng ecc = new ECDsaCng())
                {
                    ecc.ImportSubjectPublicKeyInfo(Convert.FromBase64String(publicKey), out _);
                    byte[] dataBytes = Encoding.UTF8.GetBytes(data);
                    byte[] signatureBytes = Convert.FromBase64String(signature);
                    return ecc.VerifyData(dataBytes, signatureBytes);
                }
            });
            return await taskDecrypt;
        }
    }
}
