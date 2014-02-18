using System.Security.Cryptography;

namespace PublicKeyEncryption
{
    /// <summary>
    /// Helper class for retrieving key data from the Windows store certificate.
    /// </summary>
    public class CertificateStore
    {
        /// <summary>
        /// Gets the public key only.
        /// </summary>
        /// <param name="keyContainerName">Key id used for looking up the Window certificate store.</param>
        /// <returns>Xml string containing the public key.</returns>
        public string GetPublicKey(string keyContainerName)
        {
            var rsa = new RSACryptoServiceProvider(new CspParameters { KeyContainerName = keyContainerName });
            return rsa.ToXmlString(false);
        }
    }
}
