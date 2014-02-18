
namespace PublicKeyEncryption
{
    /// <summary>
    /// Container class that stores all the data needed for
    /// transferring encrypted data between sender and receiver.
    /// </summary>
    public class Message
    {
        /// <summary>
        /// Message content
        /// </summary>
        public byte[] Data { get; set; }

        /// <summary>
        /// Encrypted key used for decrypting the cipher
        /// </summary>
        public byte[] Key { get; set; }

        /// <summary>
        /// Encrypted initialization vector used for decrypting the cipher
        /// </summary>
        public byte[] IV { get; set; }

        /// <summary>
        /// Digital signature
        /// </summary>
        public byte[] Signature { get; set; }
    }
}
