using System.Security.Cryptography;

namespace Tools.Cryptography
{
    public sealed class CryptoAes
    {
        private readonly Aes _aesProvider;

        public CryptoAes()
        {
            _aesProvider = Aes.Create();
            _aesProvider.GenerateIV();
            _aesProvider.GenerateKey();
        }

        public CryptoAes(byte[] vector, byte[] key)
        {
            _aesProvider = Aes.Create();
            _aesProvider.IV = vector;
            _aesProvider.Key = key;
        }

        public byte[] IV
        {
            get { return _aesProvider.IV; }
        }

        public byte[] Key
        {
            get { return _aesProvider.Key; }
        }

        public byte[] Encrypt(string toEncrypt)
        {
            ICryptoTransform encryptor = _aesProvider.CreateEncryptor(Key, IV);

            using (MemoryStream msEncrypt = new MemoryStream())
            {
                using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                {
                    using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                    {
                        swEncrypt.Write(toEncrypt);
                    }
                    return msEncrypt.ToArray();
                }
            }
        }

        public string Decrypt(byte[] cypher)
        {
            ICryptoTransform decryptor = _aesProvider.CreateDecryptor(Key, IV);

            using (MemoryStream msDecrypt = new MemoryStream(cypher))
            {
                using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                {
                    using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                    {
                        return srDecrypt.ReadToEnd();
                    }
                }
            }
        }
    }
}
