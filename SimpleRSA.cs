using System.Security.Cryptography;
using System;
using System.Text;

namespace SimpleCrypto
{
    public class SimpleRSA
    {
        private RSAParameters _publicKey, _privateKey;
        private string _strPublicKey, _strPrivateKey;

        public SimpleRSA(bool initialize = true, SimpleRSAKeyLength keyLength = SimpleRSAKeyLength.RSA2048)
        {
            if (!initialize)
            {
                return;
            }

            int theLength = 0;

            switch (keyLength)
            {
                case SimpleRSAKeyLength.RSA256:
                    theLength = 256;
                    break;
                case SimpleRSAKeyLength.RSA512:
                    theLength = 512;
                    break;
                case SimpleRSAKeyLength.RSA1024:
                    theLength = 1024;
                    break;
                case SimpleRSAKeyLength.RSA2048:
                    theLength = 2048;
                    break;
                case SimpleRSAKeyLength.RSA4096:
                    theLength = 4096;
                    break;
                default:
                    throw new Exception("Invalid value of the parameter \"keyLength\".");
            }

            RSACryptoServiceProvider rsa = new RSACryptoServiceProvider(theLength);

            _privateKey = rsa.ExportParameters(true);
            _publicKey = rsa.ExportParameters(false);

            _strPrivateKey = ConvertParameterToString(_privateKey);
            _strPublicKey = ConvertParameterToString(_publicKey);
        }

        private static string ConvertParameterToString(RSAParameters parameter)
        {
            var stringWriter = new System.IO.StringWriter();
            var xmlSerializer = new System.Xml.Serialization.XmlSerializer(typeof(RSAParameters));
            xmlSerializer.Serialize(stringWriter, parameter);
            return stringWriter.ToString();
        }

        private static RSAParameters ConvertStringToParameter(string str)
        {
            var stringReader = new System.IO.StringReader(str);
            var xmlSerializer = new System.Xml.Serialization.XmlSerializer(typeof(RSAParameters));
            return (RSAParameters)xmlSerializer.Deserialize(stringReader);
        }

        public string GetPublicKey()
        {
            return _strPublicKey;
        }

        public string GetPrivateKey()
        {
            return _strPrivateKey;
        }

        public void ImportPublicKey(string key)
        {
            _strPublicKey = key;
            _publicKey = ConvertStringToParameter(key);
        }

        public void ImportPrivateKey(string key)
        {
            _strPrivateKey = key;
            _privateKey = ConvertStringToParameter(key);
        }

        private byte[] RsaEncrypt(byte[] data, RSAParameters parameter)
        {
            RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
            rsa.ImportParameters(parameter);
            return rsa.Encrypt(data, false);
        }

        private byte[] RsaDecrypt(byte[] data, RSAParameters parameter)
        {
            RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
            rsa.ImportParameters(parameter);
            return rsa.Decrypt(data, false);
        }

        public byte[] EncryptPublic(byte[] data)
        {
            return RsaEncrypt(data, _publicKey);
        }

        public byte[] EncryptPublic(string data)
        {
            return EncryptPublic(Encoding.UTF8.GetBytes(data));
        }

        public byte[] DecryptPublic(byte[] data)
        {
            return RsaDecrypt(data, _publicKey);
        }

        public byte[] DecryptPublic(string data)
        {
            return DecryptPublic(Encoding.UTF8.GetBytes(data));
        }

        public byte[] EncryptPrivate(byte[] data)
        {
            return RsaEncrypt(data, _privateKey);
        }

        public byte[] EncryptPrivate(string data)
        {
            return EncryptPrivate(Encoding.UTF8.GetBytes(data));
        }

        public byte[] DecryptPrivate(byte[] data)
        {
            return RsaDecrypt(data, _privateKey);
        }

        public byte[] DecryptPrivate(string data)
        {
            return DecryptPrivate(Encoding.UTF8.GetBytes(data));
        }

        public static byte[] Encrypt(byte[] data, string key)
        {
            RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
            rsa.ImportParameters(ConvertStringToParameter(key));
            return rsa.Encrypt(data, false);
        }

        public static byte[] Decrypt(byte[] data, string key)
        {
            RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
            rsa.ImportParameters(ConvertStringToParameter(key));
            return rsa.Decrypt(data, false);
        }

        public static byte[] Encrypt(string data, string key)
        {
            return Encrypt(Encoding.UTF8.GetBytes(data), key);
        }

        public static byte[] Decrypt(string data, string key)
        {
            return Decrypt(Encoding.UTF8.GetBytes(data), key);
        }

        public static Tuple<string, string> GenerateKeys(SimpleRSAKeyLength keyLength = SimpleRSAKeyLength.RSA2048)
        {
            int theLength = 0;

            switch (keyLength)
            {
                case SimpleRSAKeyLength.RSA256:
                    theLength = 256;
                    break;
                case SimpleRSAKeyLength.RSA512:
                    theLength = 512;
                    break;
                case SimpleRSAKeyLength.RSA1024:
                    theLength = 1024;
                    break;
                case SimpleRSAKeyLength.RSA2048:
                    theLength = 2048;
                    break;
                case SimpleRSAKeyLength.RSA4096:
                    theLength = 4096;
                    break;
                default:
                    throw new Exception("Invalid value of the parameter \"keyLength\".");
            }

            RSACryptoServiceProvider rsa = new RSACryptoServiceProvider(theLength);

            RSAParameters privateKey = rsa.ExportParameters(true);
            RSAParameters publicKey = rsa.ExportParameters(false);

            string strPrivateKey = ConvertParameterToString(privateKey);
            string strPublicKey = ConvertParameterToString(publicKey);

            return new Tuple<string, string>(strPublicKey, strPrivateKey);
        }
    }

    public enum SimpleRSAKeyLength
    {
        RSA256,
        RSA512,
        RSA1024,
        RSA2048,
        RSA4096
    }
}