using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using POC.EncryptionData.Common;
using System.Security.Cryptography;
using static System.Net.Mime.MediaTypeNames;


namespace POC.EncryptionData.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class EncryptionAesController : ControllerBase
    {

        [HttpGet]
        [Route("encrypt")]

        public async Task<ActionResult> Encrypt(string plaintext)
        {
            // Encrypt
            byte[] ciphertext = await AesEncryptionManager.Encrypt(plaintext);
            string encryptedText = Convert.ToBase64String(ciphertext);

            return Ok(new { EncryptedText = encryptedText });
        }

        [HttpGet]
        [Route("decrypt")]

        public async Task<ActionResult> Decrypt(string encryptedText)
        {
            // Decrypt
            byte[] bytes = Convert.FromBase64String(encryptedText);
            string decryptedText = await AesEncryptionManager.Decrypt(bytes);

            return Ok(new { DecryptedText = decryptedText });
        }







    }
}