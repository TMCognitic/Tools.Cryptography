using System.Security.Cryptography;
using System.Text;

namespace Tools.Cryptography
{
    public class CryptoRSA
    {
        private readonly RSACryptoServiceProvider _serviceProvider;

        public CryptoRSA(in int keySize)
        {
            _serviceProvider = new RSACryptoServiceProvider(keySize);            
        }

        public CryptoRSA(in byte[] keyBlob)
        {
            _serviceProvider = new RSACryptoServiceProvider();
            _serviceProvider.ImportCspBlob(keyBlob);
        }

        public int KeySize
        {
            get { return _serviceProvider.KeySize; }
        }

        public int MaxContentSize
        {
            //Key Size in Byte - 2 * Hash Size in octet - 2
            get { return (KeySize / 8) - (2 * 20) - 2; }
        }

        public bool PublicKeyOnly
        {
            get { return _serviceProvider.PublicOnly; }
        }

        public string ToXml(in bool includePrivateKey)
        {
            return _serviceProvider.ToXmlString(includePrivateKey);
        }

        public byte[] ToByteArray(in bool includePrivateKey)
        {
            return _serviceProvider.ExportCspBlob(includePrivateKey);
        }

        public byte[] Encrypt(in string content)
        {
            if (content.Length > MaxContentSize)
                throw new InvalidOperationException($"With the current key you can encrypt a string with max size : {MaxContentSize}");

            byte[] toEncode = Encoding.Unicode.GetBytes(content);
            return _serviceProvider.Encrypt(toEncode, true);
        }

        public string Decrypt(in byte[] cypher)
        {
            if (PublicKeyOnly)
                throw new InvalidOperationException("Only the private key can decrypt.");

            byte[] decodedData = _serviceProvider.Decrypt(cypher, true);
            return Encoding.Unicode.GetString(decodedData);
        }

        public byte[] Sign(in byte[] cypher)
        {
            if (PublicKeyOnly)
                throw new InvalidOperationException("Only the private key can sign.");

            return _serviceProvider.SignData(cypher, SHA512.Create());
        }

        public bool Verify(in byte[] cypher, in byte[] signedData)
        {
            return _serviceProvider.VerifyData(cypher, SHA512.Create(), signedData);
        }
    }
}