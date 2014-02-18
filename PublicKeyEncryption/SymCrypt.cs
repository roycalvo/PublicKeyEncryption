using System.IO;
using System.Security.Cryptography;

namespace PublicKeyEncryption
{
    /// <summary>
    /// Provides methods for encrypting and decrypting
    /// using symmetric algorithms.
    /// </summary>
    public class SymCrypt
    {
        private readonly SymmetricAlgorithm _alg;
        private readonly byte[] _key;
        private readonly byte[] _iv;

        public byte[] Key { get { return _alg.Key; } }
        public byte[] Iv { get { return _alg.IV; } }

        public SymCrypt(SymmetricAlgorithm alg)
        {
            _alg = alg;
        }

        public byte[] Encrypt(byte[] data)
        {
            return transform(_alg.CreateEncryptor(), data);
        }

        public byte[] Decrypt(byte[] data)
        {
            return transform(_alg.CreateDecryptor(), data);
        }

        private byte[] transform(ICryptoTransform transform, byte[] data)
        {
            var memStream = new MemoryStream();
            var cryptStream = new CryptoStream(memStream, transform, CryptoStreamMode.Write);
            cryptStream.Write(data, 0, data.Length);
            cryptStream.FlushFinalBlock();

            memStream.Position = 0;
            byte[] result = new byte[memStream.Length];
            memStream.Read(result, 0, result.Length);
            memStream.Close();

            return result;
        }
    }
}
