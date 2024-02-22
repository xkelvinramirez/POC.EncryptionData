using Microsoft.AspNetCore.DataProtection.KeyManagement;
using System.Security.Cryptography;
using System.Text;

namespace POC.EncryptionData.Common
{
    public static class AesEncryptionManager
    {
        internal static readonly byte[] Key1 = new byte[32] // 32 bytes = 256-bit.
        {
            73, 84, 28, 39, 182, 122, 193, 73, 43, 71, 106, 142, 76, 16, 54, 19, 21, 115, 138, 75, 45, 114, 41, 79, 181, 196, 40, 148, 154, 81, 173, 56
        };

        public static string generateKeyAes()
        {
            #region v1
            byte[] key = new byte[32]; // 256-bit key
            byte[] iv = new byte[16]; // 128-bit IV
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(key);
                rng.GetBytes(iv);
            }
            #endregion

            #region v2
            string keyBase64Key = string.Empty;
            //"Creating Aes Encryption 256 bit key"
            using (Aes aesAlgorithm = Aes.Create())
            {
                aesAlgorithm.KeySize = 256;
                aesAlgorithm.GenerateKey();
                keyBase64Key = Convert.ToBase64String(aesAlgorithm.Key);
                Console.WriteLine($"Aes Key Size : {aesAlgorithm.KeySize}");
                Console.WriteLine($"keyBase64Key Size : {keyBase64Key.Length}");
                Console.WriteLine("Here is the Aes key in Base64:");
                Console.WriteLine(keyBase64Key);
            }
            #endregion

            return keyBase64Key;
        }
        public static async Task<byte[]> Encrypt(string plaintext)
        {
            var taskEncrypt = Task.Run(() =>
            {
                byte[] iv_ = new byte[16];
                using (Aes aesAlg = Aes.Create())
                {
                    aesAlg.Key = Key1;
                    aesAlg.IV = iv_;
                    ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);
                    byte[] encryptedBytes;
                    using (var msEncrypt = new System.IO.MemoryStream())
                    {
                        using (var csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                        {
                            byte[] plainBytes = Encoding.UTF8.GetBytes(plaintext);
                            csEncrypt.Write(plainBytes, 0, plainBytes.Length);
                        }
                        encryptedBytes = msEncrypt.ToArray();
                    }
                    return encryptedBytes;
                }
            });
            return await taskEncrypt;
        }

        public static async Task<string> Decrypt(byte[] ciphertext)
        {
            var taskDecrypt = Task.Run(() =>
            {
                byte[] iv_ = new byte[16];
                using (Aes aesAlg = Aes.Create())
                {
                    aesAlg.Key = Key1;
                    aesAlg.IV = iv_;
                    ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);
                    byte[] decryptedBytes;
                    using (var msDecrypt = new System.IO.MemoryStream(ciphertext))
                    {
                        using (var csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                        {
                            using (var msPlain = new System.IO.MemoryStream())
                            {
                                csDecrypt.CopyTo(msPlain);
                                decryptedBytes = msPlain.ToArray();
                            }
                        }
                    }
                    return Encoding.UTF8.GetString(decryptedBytes);
                }
            });

            return await taskDecrypt;
        }




        #region old
        private static readonly string Key = "tu_clave_secreta_de_32_bytes";
        private static readonly string IV = "tu_vector_de_inicializacion_de_16_bytes";
        public static string Encrypt_old(string plainText)
        {
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = Encoding.UTF8.GetBytes(Key);
                aesAlg.IV = Encoding.UTF8.GetBytes(IV);

                ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                        {
                            swEncrypt.Write(plainText);
                        }
                    }
                    return Convert.ToBase64String(msEncrypt.ToArray());
                }
            }
        }

        public static string Decrypt(string cipherText)
        {
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = Encoding.UTF8.GetBytes(Key);
                aesAlg.IV = Encoding.UTF8.GetBytes(IV);

                ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

                using (MemoryStream msDecrypt = new MemoryStream(Convert.FromBase64String(cipherText)))
                {
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                        {
                            return srDecrypt.ReadToEnd();
                        }
                    }
                }
            }
        }

        public static string Encrypt(string PlainText, string Password,
              string Salt = "Kosher", string HashAlgorithm = "SHA1",
              int PasswordIterations = 2, string InitialVector = "OFRna73m*aze01xY",
              int KeySize = 256)
        {
            if (string.IsNullOrEmpty(PlainText))
                return "";
            byte[] InitialVectorBytes = Encoding.ASCII.GetBytes(InitialVector);
            byte[] SaltValueBytes = Encoding.ASCII.GetBytes(Salt);
            byte[] PlainTextBytes = Encoding.UTF8.GetBytes(PlainText);
            PasswordDeriveBytes DerivedPassword = new PasswordDeriveBytes(Password, SaltValueBytes, HashAlgorithm, PasswordIterations);
            byte[] KeyBytes = DerivedPassword.GetBytes(KeySize / 8);
            // Disable the warning.
#pragma warning disable SYSLIB0022
            RijndaelManaged SymmetricKey = new RijndaelManaged();
            SymmetricKey.Mode = CipherMode.CBC;
            byte[]? CipherTextBytes = null;
            using (ICryptoTransform Encryptor = SymmetricKey.CreateEncryptor(KeyBytes, InitialVectorBytes))
            {
                using (MemoryStream MemStream = new MemoryStream())
                {
                    using (CryptoStream CryptoStream = new CryptoStream(MemStream, Encryptor, CryptoStreamMode.Write))
                    {
                        CryptoStream.Write(PlainTextBytes, 0, PlainTextBytes.Length);
                        CryptoStream.FlushFinalBlock();
                        CipherTextBytes = MemStream.ToArray();
                        MemStream.Close();
                        CryptoStream.Close();
                    }
                }
            }
            SymmetricKey.Clear();
            return Convert.ToBase64String(CipherTextBytes);
        }

        public static string Decrypt(string CipherText, string Password,
              string Salt = "Kosher", string HashAlgorithm = "SHA1",
              int PasswordIterations = 2, string InitialVector = "OFRna73m*aze01xY",
              int KeySize = 256)
        {
            if (string.IsNullOrEmpty(CipherText))
                return "";
            byte[] InitialVectorBytes = Encoding.ASCII.GetBytes(InitialVector);
            byte[] SaltValueBytes = Encoding.ASCII.GetBytes(Salt);
            byte[] CipherTextBytes = Convert.FromBase64String(CipherText);
            PasswordDeriveBytes DerivedPassword = new PasswordDeriveBytes(Password, SaltValueBytes, HashAlgorithm, PasswordIterations);
            byte[] KeyBytes = DerivedPassword.GetBytes(KeySize / 8);
            RijndaelManaged SymmetricKey = new RijndaelManaged();
            SymmetricKey.Mode = CipherMode.CBC;
            byte[] PlainTextBytes = new byte[CipherTextBytes.Length];
            int ByteCount = 0;
            using (ICryptoTransform Decryptor = SymmetricKey.CreateDecryptor(KeyBytes, InitialVectorBytes))
            {
                using (MemoryStream MemStream = new MemoryStream(CipherTextBytes))
                {
                    using (CryptoStream CryptoStream = new CryptoStream(MemStream, Decryptor, CryptoStreamMode.Read))
                    {

                        ByteCount = CryptoStream.Read(PlainTextBytes, 0, PlainTextBytes.Length);
                        MemStream.Close();
                        CryptoStream.Close();
                    }
                }
            }
            SymmetricKey.Clear();
            return Encoding.UTF8.GetString(PlainTextBytes, 0, ByteCount);
        }

        #endregion 
    }
}
