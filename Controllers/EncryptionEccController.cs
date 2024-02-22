using Microsoft.AspNetCore.Mvc;
using POC.EncryptionData.Common;
using POC.EncryptionData.Commons.Constants;
using POC.EncryptionData.Dtos;

namespace POC.EncryptionData.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class EncryptionEccController : Controller
    {
        [HttpGet]
        [Route("encrypt")]

        public async Task<ActionResult> Encrypt(string strValue)
        {
            var signature = await EccEncryptionManager.SignECC(ProjectConstants.ECC_KEY_PRIVATE, strValue);

            return Ok(new { Signature = signature });

        }

        [HttpPost]
        [Route("encryptBase64")]

        public async Task<ActionResult> EncryptBase64(EncryptionDto value)
        {
            var signature = await EccEncryptionManager.SignECC(ProjectConstants.ECC_KEY_PRIVATE, value.strBase64);

            return Ok(new { Signature = signature });

        }

        [HttpGet]
        [Route("decrypt")]

        public async Task<ActionResult> Decrypt(string strValue, string signature)
        {

            var respVerify = await EccEncryptionManager.VerifyECC(ProjectConstants.ECC_KEY_PUBLIC, strValue, signature);

            return Ok(new { Signature = signature, Verify = respVerify });

        }
    }
}
