using System;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace Order.Core
{
    static class Security
    {
        internal static string Md5(byte[] data, string format)
        {
            using (var md5 = MD5.Create())
                return string.Concat(md5.ComputeHash(data).Select(x => x.ToString(format)));
        }

        static byte[] AesTransform(byte[] data, byte[] key, Func<Aes, ICryptoTransform> cryptor)
        {
            try
            {
                using (var aes = Aes.Create())
                {
                    aes.Key = key;
                    aes.IV = new byte[16];
                    aes.Mode = CipherMode.CBC;
                    aes.Padding = PaddingMode.PKCS7;

                    using (var crypt = cryptor(aes))
                        return crypt.TransformFinalBlock(data, 0, data.Length);
                }
            }
            catch(Exception ex)
            {
                return null;
            }
        }

        internal static byte[] AesEncrypt(byte[] data, byte[] key)
        {
            return AesTransform(data, key, aes => aes.CreateEncryptor());
        }

        internal static byte[] AesDecrypt(byte[] data, byte[] key)
        {
            return AesTransform(data, key, aes => aes.CreateDecryptor());
        }

        internal static class RSA
        {
            internal static byte[] SignData(byte[] data, string privateKey)
            {
                try
                {
                    using (var key = CngKey.Import(Convert.FromBase64String(privateKey), CngKeyBlobFormat.Pkcs8PrivateBlob))
                    using (var rsa = new RSACng(key))
                        return rsa.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                }
                catch
                {
                    return null;
                }
            }

            internal static bool VerifySign(byte[] data, byte[] signature, string publicKey)
            {
                try
                {
                    var para = ConvertFromPublicKey(Convert.FromBase64String(publicKey));
                    using (var rsa = new RSACryptoServiceProvider())
                    {
                        rsa.ImportParameters(para);
                        return rsa.VerifyData(data, "SHA256", signature);
                    }
                }
                catch
                {
                    return false;
                }
            }

            static RSAParameters ConvertFromPublicKey(byte[] publickKey)
            {
                var pemModulus = new byte[256];
                var pemPublicExponent = new byte[3];
                Array.Copy(publickKey, 33, pemModulus, 0, 256);
                Array.Copy(publickKey, 291, pemPublicExponent, 0, 3);
                var para = new RSAParameters()
                {
                    Modulus = pemModulus,
                    Exponent = pemPublicExponent
                };
                return para;
            }
        }
    }
}
