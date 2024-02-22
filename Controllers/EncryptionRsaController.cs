using Microsoft.AspNetCore.Mvc;
using POC.EncryptionData.Common;
using POC.EncryptionData.Commons.Constants;
using POC.EncryptionData.Dtos;

namespace POC.EncryptionData.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class EncryptionRsaController : ControllerBase
    {
        [HttpGet]
        [Route("encrypt")]

        public async Task<ActionResult> Encrypt(string strValue)
        {
            var encryptedText = await RsaEncryptionManager.EncryptRSA(ProjectConstants.RSA_KEY_PUBLIC, strValue);

            return Ok(new { EncryptedText = encryptedText });
        }

        [HttpPost]
        [Route("encryptBase64")]

        public async Task<ActionResult> EncryptBase64(EncryptionDto value)
        {
            var encryptedText = await RsaEncryptionManager.EncryptRSA(ProjectConstants.RSA_KEY_PUBLIC, value.strBase64);

            return Ok(new { EncryptedText = encryptedText });
        }

        [HttpGet]
        [Route("decrypt")]

        public async Task<ActionResult> Decrypt(string encryptedText)
        {
            var decryptedText = await RsaEncryptionManager.DecryptRSA(ProjectConstants.RSA_KEY_PRIVATE, encryptedText);

            return Ok(new { DecryptedText = decryptedText });
        }
    }
}
