using System.Security.Cryptography;
using System.Text;

namespace PublicKeyEncryption
{
    /// <summary>
    /// Provides methods for encrypting and decrypting
    /// using asymmetric algorithms.
    /// </summary>
    public class RsaCrypt
    {
        private RSACryptoServiceProvider _rsa;

        /// <summary>
        /// Retrieves the public/private key pair from a certificate in the
        /// Windows certificate store and creates an instance of RSACryptoserviceProvider.
        /// </summary>
        /// <param name="keyContainerName">String value used for retrieving the certificate data from the Windows certificate store.</param>
        public RsaCrypt(string keyContainerName)
        {
            _rsa = new RSACryptoServiceProvider(new CspParameters { KeyContainerName = keyContainerName });
        }

        public Message SignAndEncrypt(string message, string receiverPublicKey)
        {
            // convert message in bytes
            byte[] messageBytes = (new UTF8Encoding()).GetBytes(message);

            // Sign the clear text using the sender's private key
            byte[] signature = signMessage(messageBytes);
            var result = new Message { Signature = signature };

            // Encrypt the clear text using symmetrical encryption
            var cryptor = new SymCrypt(new RijndaelManaged());
            byte[] encryptedData = cryptor.Encrypt(messageBytes);
            result.Data = encryptedData;

            // Get recipient's public key
            var receiverRsa = new RSACryptoServiceProvider();
            receiverRsa.FromXmlString(receiverPublicKey);

            // Encrypt the encryption keys using the receiver's public key.
            result.Key = receiverRsa.Encrypt(cryptor.Key, false);
            result.IV = receiverRsa.Encrypt(cryptor.Iv, false);

            return result;
        }

        public string DecryptAndVerifySignature(Message message, string senderPublicKey)
        {
            // Decrypt keys using recipient's private key
            byte[] key = _rsa.Decrypt(message.Key, false);
            byte[] iv = _rsa.Decrypt(message.IV, false);

            // Get sender's public key
            var senderRsa = new RSACryptoServiceProvider();
            senderRsa.FromXmlString(senderPublicKey);

            // Decrypt the cipher text using symmetrical encryption
            var alg = new RijndaelManaged { Key = key, IV = iv };
            var cryptor = new SymCrypt(alg);
            byte[] clearTextBytes = cryptor.Decrypt(message.Data);

            // Verify digital signature using the sender's public key.
            bool verified = verifySignature(clearTextBytes, message.Signature, senderRsa);

            string clearText = (new UTF8Encoding()).GetString(clearTextBytes);

            return verified ? clearText : null;
        }

        private byte[] signMessage(byte[] messageBytes)
        {
            //// compute hash of the clear text message
            //var sha1 = new SHA1CryptoServiceProvider();
            //byte[] sha1Hash = sha1.ComputeHash(messageBytes);

            //// sign hash using the sender's private key
            //byte[] signature = _rsa.SignHash(sha1Hash, CryptoConfig.MapNameToOID("SHA1"));

            // ** shorter way to do the same thing **
            // Sign the clear text using the sender's private key
            byte[] signature = _rsa.SignData(messageBytes, new SHA1CryptoServiceProvider());

            return signature;
        }

        private bool verifySignature(byte[] messageBytes, byte[] signature, RSACryptoServiceProvider senderRsa)
        {
            //// compute hash of the clear text message
            //var sha1 = new SHA1CryptoServiceProvider();
            //byte[] sha1Hash = sha1.ComputeHash(messageBytes);

            //bool result = senderRsa.VerifyHash(sha1Hash, CryptoConfig.MapNameToOID("SHA1"), signature);

            // ** shorter way to do the same thing **
            // Verify digital signature using the sender's public key.
            bool result = senderRsa.VerifyData(messageBytes, new SHA1CryptoServiceProvider(), signature);

            return result;
        }
    }
}
