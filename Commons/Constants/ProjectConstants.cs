using POC.EncryptionData.Common;

namespace POC.EncryptionData.Commons.Constants
{
    public static class ProjectConstants
    {
        //(string publicKey, string privateKey) _keysRsa = RsaEncryptionManager.GenerateKeys();
        //(string publicKey, string privateKey) _keysEcc = EccEncryptionManager.GenerateKeysECC();

        public static readonly string RSA_KEY_PUBLIC = "<RSAKeyValue><Modulus>4mRZyPPxaUMmgOuzLprRVecJzsGwDggZ2HjYT9j8tr/HSmiDNLRanzo+j7SywMUVPhfNLAni3NHBEorfcQDbC5Xe9o0qqd4s9qYJqLUtsBZ+GlolxkoGsl09pnaZw9QCVmcxy/icuGvWbVbFB5dIJDvskHmozhp+93IZx8Yw5Ak=</Modulus><Exponent>AQAB</Exponent></RSAKeyValue>";
        public static readonly string RSA_KEY_PRIVATE = "<RSAKeyValue><Modulus>4mRZyPPxaUMmgOuzLprRVecJzsGwDggZ2HjYT9j8tr/HSmiDNLRanzo+j7SywMUVPhfNLAni3NHBEorfcQDbC5Xe9o0qqd4s9qYJqLUtsBZ+GlolxkoGsl09pnaZw9QCVmcxy/icuGvWbVbFB5dIJDvskHmozhp+93IZx8Yw5Ak=</Modulus><Exponent>AQAB</Exponent><P>47LKcvnueG+Rn5VMNy5EbiEd3dM7eRaaszCBpfzsSbdBo7b1F/qHJpHGAIx0GBi6mnWajkSvRguS+M0vJm1/6w==</P><Q>/of9rZzDMTFTXiCGZNwUxNFaHayYw85u1tang7HCK4gL9QRUypEqCxWXbcGvtmqkQ2WS3ZHE6tVIYEmyNAXi2w==</Q><DP>MVe7W3Mh5GN5ETYPUB3solj22e0+hB0L5Szry4alxcu6o7mwH0QhKZCJcfD974LcXUCC/7WOrgUwEk6UmyU7hQ==</DP><DQ>vc7bteP5C24lJURL9FrKghs8gHR9V0dSEJPyR5r/mUbS49xe/tBR8gIf8pFFX1sXM8tDQke5+QUj++n5IiJhkQ==</DQ><InverseQ>0wIPHPVivdOsDRRqrBkciiUMt1bkc0elrCzebjLqlscoyuix8ff1dYaglUjSFy0Bl2G5j8gAt9wLb1159OrN+w==</InverseQ><D>TMR4iaLmtqn1kXvbS69l0rpAYiLdnzRyByybNSBAOXv4iSu9ag7KN/oZIsPEZYeu91o80XUcv4JE9ROwRvJiU/zdbHyXBHBVGtu4af4mNJ1+SPXNUbHQOx47+OsvQBTdD8xq9RukdI3vTXancgAvcTm/rZYPQTvtyFtW12mrXf0=</D></RSAKeyValue>";

        public static readonly string ECC_KEY_PUBLIC = "MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQBPC8vNGKd7VVEtodXceZmOygoI6IMxqew+RVySLzK0JtGtL1ysE17Gytd1s7bBVL6kOMRfGEhHr+XCdhM3j1azekAz/cE9Wa2S7byEiPS+YccAaOlTCA1/fKOF2z0iQTPahVHg7br32qdc3iAs7oZQaAjr1NcnSEj1i653zzWlOtiYcY=";
        public static readonly string ECC_KEY_PRIVATE = "MIHcAgEBBEIAzofuc3flwW6DamsmMrm5yqZmjUCa/TF/K0+FQQoHaXkqTMYL15cWSZJyhhb5yEc9SGtIilsEAkxX/939XPR8wG+gBwYFK4EEACOhgYkDgYYABAE8Ly80Yp3tVUS2h1dx5mY7KCgjogzGp7D5FXJIvMrQm0a0vXKwTXsbK13WztsFUvqQ4xF8YSEev5cJ2EzePVrN6QDP9wT1ZrZLtvISI9L5hxwBo6VMIDX98o4XbPSJBM9qFUeDtuvfap1zeICzuhlBoCOvU1ydISPWLrnfPNaU62Jhxg==";
    }
}
