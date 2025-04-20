using System;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
using System.Text;
using System.Security.Cryptography;

namespace SimpleCrypto
{
    public class SimpleAES
    {
        private static SimpleRandom _random = new SimpleRandom(5);

        private static byte[] Process(byte[] data, byte[] key, byte[] iv, bool isEncrypt)
        {
            IBufferedCipher cipher = CipherUtilities.GetCipher("AES/GCM/NoPadding");
            KeyParameter keyParameter = ParameterUtilities.CreateKeyParameter("AES", key);
            ParametersWithIV parameters = new ParametersWithIV(keyParameter, iv);
            cipher.Init(isEncrypt, parameters);

            byte[] processed = new byte[cipher.GetOutputSize(data.Length)];
            int len = cipher.ProcessBytes(data, 0, data.Length, processed, 0);
            cipher.DoFinal(processed, len);

            return processed;
        }

        public static byte[] Encrypt(byte[] data, byte[] key, byte[] iv)
        {
            return Process(data, key, iv, true);
        }

        public static byte[] Decrypt(byte[] data, byte[] key, byte[] iv)
        {
            return Process(data, key, iv, false);
        }

        public static byte[] Encrypt(string data, byte[] key, byte[] iv)
        {
            return Process(Encoding.UTF8.GetBytes(data), key, iv, true);
        }

        public static byte[] Decrypt(string data, byte[] key, byte[] iv)
        {
            return Process(Encoding.UTF8.GetBytes(data), key, iv, false);
        }

        public static byte[] Encrypt(byte[] data, byte[] key)
        {
            return Process(data, key, new byte[16], true);
        }

        public static byte[] Decrypt(byte[] data, byte[] key)
        {
            return Process(data, key, new byte[16], false);
        }

        public static byte[] Encrypt(string data, byte[] key)
        {
            return Process(Encoding.UTF8.GetBytes(data), key, new byte[16], true);
        }

        public static byte[] Decrypt(string data, byte[] key)
        {
            return Process(Encoding.UTF8.GetBytes(data), key, new byte[16], false);
        }

        public static byte[] GetRandomKey(SimpleAESKeyLength keyLength = SimpleAESKeyLength.AES256)
        {
            switch (keyLength)
            {
                case SimpleAESKeyLength.AES128:
                    return _random.GetRandomBytes(16);
                case SimpleAESKeyLength.AES192:
                    return _random.GetRandomBytes(24);
                case SimpleAESKeyLength.AES256:
                    return _random.GetRandomBytes(32);
            }

            throw new Exception("Invalid value of the parameter \"keyLength\".");
        }

        public static byte[] GetRandomIV(byte ivLength = 16)
        {
            if (ivLength < 8 || ivLength > 16)
            {
                throw new Exception("Invalid IV length (parameter \"ivLength\"): it must be between 8 and 16.");
            }

            return _random.GetRandomBytes(ivLength);
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

        public static byte[] GetSecureIV(byte[] dataToHash)
        {
            return MD5.Create().ComputeHash(dataToHash);
        }

        public static byte[] GetSecureKey(string dataToHash)
        {
            return GetSecureKey(Encoding.UTF8.GetBytes(dataToHash));
        }

        public static byte[] GetSecureIV(string dataToHash)
        {
            return GetSecureIV(Encoding.UTF8.GetBytes(dataToHash));
        }
    }

    public enum SimpleAESKeyLength
    {
        AES128,
        AES192,
        AES256
    }
}