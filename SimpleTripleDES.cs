using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace SimpleCrypto
{
    public class SimpleTripleDES
    {
        private static SimpleRandom _random = new SimpleRandom(5);

        public static byte[] Encrypt(byte[] data, byte[] key, byte[] iv)
        {
            TripleDESCryptoServiceProvider provider = new TripleDESCryptoServiceProvider();
            ICryptoTransform transform = provider.CreateEncryptor(key, iv);
            CryptoStreamMode mode = CryptoStreamMode.Write;

            MemoryStream memStream = new MemoryStream();
            CryptoStream cryptoStream = new CryptoStream(memStream, transform, mode);
            cryptoStream.Write(data, 0, data.Length);
            cryptoStream.FlushFinalBlock();

            byte[] encryptedMessageBytes = new byte[memStream.Length];
            memStream.Position = 0;
            memStream.Read(encryptedMessageBytes, 0, encryptedMessageBytes.Length);

            return encryptedMessageBytes;
        }

        public static byte[] Decrypt(byte[] data, byte[] key, byte[] iv)
        {
            TripleDESCryptoServiceProvider provider = new TripleDESCryptoServiceProvider();
            ICryptoTransform transform = provider.CreateDecryptor(key, iv);
            CryptoStreamMode mode = CryptoStreamMode.Write;

            MemoryStream memStream = new MemoryStream();
            CryptoStream cryptoStream = new CryptoStream(memStream, transform, mode);
            cryptoStream.Write(data, 0, data.Length);
            cryptoStream.FlushFinalBlock();

            byte[] decryptedMessageBytes = new byte[memStream.Length];
            memStream.Position = 0;
            memStream.Read(decryptedMessageBytes, 0, decryptedMessageBytes.Length);

            return decryptedMessageBytes;
        }

        public static byte[] Encrypt(string data, byte[] key, byte[] iv)
        {
            return Encrypt(Encoding.UTF8.GetBytes(data), key, iv);
        }

        public static byte[] Decrypt(string data, byte[] key, byte[] iv)
        {
            return Decrypt(Encoding.UTF8.GetBytes(data), key, iv);
        }

        public static byte[] Encrypt(string data, byte[] key)
        {
            return Encrypt(Encoding.UTF8.GetBytes(data), key, new byte[8]);
        }

        public static byte[] Decrypt(string data, byte[] key)
        {
            return Decrypt(Encoding.UTF8.GetBytes(data), key, new byte[8]);
        }

        public static byte[] GetRandomIV()
        {
            return _random.GetRandomBytes(8);
        }

        public static byte[] StringToBytes(string str)
        {
            return Encoding.UTF8.GetBytes(str);
        }

        public static byte[] StringToBytes(string str, Encoding encoding)
        {
            return encoding.GetBytes(str);
        }

        public static byte[] GetSecureKey(byte[] dataToHash)
        {
            return SHA256.Create().ComputeHash(dataToHash);
        }

        public static byte[] GetSecureKey(string dataToHash)
        {
            return GetSecureKey(Encoding.UTF8.GetBytes(dataToHash));
        }

        public static byte[] GetRandomKey(SimpleTripleDESKeyLength keyLength = SimpleTripleDESKeyLength.Key256)
        {
            switch (keyLength)
            {
                case SimpleTripleDESKeyLength.Key128:
                    return _random.GetRandomBytes(16);
                case SimpleTripleDESKeyLength.Key192:
                    return _random.GetRandomBytes(24);
                case SimpleTripleDESKeyLength.Key256:
                    return _random.GetRandomBytes(32);
            }

            throw new Exception("Invalid value of the parameter \"keyLength\".");
        }
    }

    public enum SimpleTripleDESKeyLength
    {
        Key128,
        Key192,
        Key256
    }
}