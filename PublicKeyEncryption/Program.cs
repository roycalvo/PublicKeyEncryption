using System;

namespace PublicKeyEncryption
{
    class Program
    {
        static void Main(string[] args)
        {
            var certStore = new CertificateStore();

            // In this scenario, Alice sends an encrypted message to Bob
            string senderId = "alice@codeblog.com";
            string receiverId = "bob@codeblog.com";

            // *** (Sender) Alice ***
            var sender = new RsaCrypt(senderId);

            // Alice gets Bob's public key, so she can encrypt the message
            string receiverPublicKey = certStore.GetPublicKey(receiverId);

            // Alice signs (using her private key) and encrypts the message (using Bob's public key)
            Message message = sender.SignAndEncrypt("this is the secret message.", receiverPublicKey);

            // *** ENCRYPTED MESSAGE SENT ***

            // *** (Receiver) Bob  ***
            var receiver = new RsaCrypt(receiverId);

            // Bob gets Alice's public key, so he can decipher the message
            string senderPublicKey = certStore.GetPublicKey(senderId);

            // Bob deciphers the encrypted message (using his private key) and verifies the signature (using Alice's public key)
            string clearText = receiver.DecryptAndVerifySignature(message, senderPublicKey);

            Console.WriteLine(clearText);
        }
    }
}
