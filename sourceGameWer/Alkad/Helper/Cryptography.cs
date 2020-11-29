using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace GameWer.Helper
{
    public class Cryptography
    {
        public static string OpenSSLEncrypt(string plainText, string passphrase)
        {
            var numArray = new byte[8];
            new RNGCryptoServiceProvider().GetNonZeroBytes(numArray);
            DeriveKeyAndIV(passphrase, numArray, out var key, out var iv);
            var bytesAes = EncryptStringToBytesAes(plainText, key, iv);
            var inArray = new byte[numArray.Length + bytesAes.Length + 8];
            Buffer.BlockCopy(Encoding.ASCII.GetBytes("Salted__"), 0, inArray, 0, 8);
            Buffer.BlockCopy(numArray, 0, inArray, 8, numArray.Length);
            Buffer.BlockCopy(bytesAes, 0, inArray, numArray.Length + 8, bytesAes.Length);
            return Convert.ToBase64String(inArray);
        }

        public static string OpenSSLDecrypt(string encrypted, string passphrase)
        {
            var numArray = Convert.FromBase64String(encrypted);
            var salt = new byte[8];
            var cipherText = new byte[numArray.Length - salt.Length - 8];
            Buffer.BlockCopy(numArray, 8, salt, 0, salt.Length);
            Buffer.BlockCopy(numArray, salt.Length + 8, cipherText, 0, cipherText.Length);
            DeriveKeyAndIV(passphrase, salt, out var key, out var iv);
            return DecryptStringFromBytesAes(cipherText, key, iv);
        }

        private static void DeriveKeyAndIV(
          string passphrase,
          byte[] salt,
          out byte[] key,
          out byte[] iv)
        {
            List<byte> list = new List<byte>(48);
            byte[] bytes = Encoding.UTF8.GetBytes(passphrase + "Challenge");
            byte[] numArray = new byte[0];
            MD5 md = MD5.Create();
            bool flag = false;
            while (!flag)
            {
                int num = numArray.Length + bytes.Length + salt.Length;
                byte[] buffer = new byte[num];
                Buffer.BlockCopy(numArray, 0, buffer, 0, numArray.Length);
                Buffer.BlockCopy(bytes, 0, buffer, numArray.Length, bytes.Length);
                Buffer.BlockCopy(salt, 0, buffer, numArray.Length + bytes.Length, salt.Length);
                numArray = md.ComputeHash(buffer);
                list.AddRange(numArray);
                bool flag2 = list.Count >= 48;
                if (flag2)
                {
                    flag = true;
                }
            }
            key = new byte[32];
            iv = new byte[16];
            list.CopyTo(0, key, 0, 32);
            list.CopyTo(32, iv, 0, 16);
            md.Clear();
        }

        private static byte[] EncryptStringToBytesAes(string plainText, byte[] key, byte[] iv)
        {
            if (plainText == null || plainText.Length <= 0)
                throw new ArgumentNullException(nameof(plainText));
            if (key == null || key.Length == 0)
                throw new ArgumentNullException(nameof(key));
            if (iv == null || iv.Length == 0)
                throw new ArgumentNullException(nameof(iv));
            RijndaelManaged rijndaelManaged = null;
            MemoryStream memoryStream;
            try
            {
                rijndaelManaged = new RijndaelManaged
                {
                    Mode = CipherMode.CFB,
                    KeySize = 256,
                    BlockSize = 128,
                    Key = key,
                    IV = iv
                };
                ICryptoTransform transform = rijndaelManaged.CreateEncryptor(rijndaelManaged.Key, rijndaelManaged.IV);
                memoryStream = new MemoryStream();
                using (CryptoStream cryptoStream = new CryptoStream(memoryStream, transform, CryptoStreamMode.Write))
                {
                    using (StreamWriter streamWriter = new StreamWriter(cryptoStream))
                    {
                        streamWriter.Write(plainText);
                        streamWriter.Flush();
                        streamWriter.Close();
                    }
                }
            }
            finally
            {
                bool flag4 = rijndaelManaged != null;
                if (flag4)
                {
                    rijndaelManaged.Clear();
                }
            }
            return memoryStream.ToArray();
        }

        private static string DecryptStringFromBytesAes(byte[] cipherText, byte[] key, byte[] iv)
        {
            if (cipherText == null || cipherText.Length == 0)
                throw new ArgumentNullException(nameof(cipherText));
            if (key == null || key.Length == 0)
                throw new ArgumentNullException(nameof(key));
            if (iv == null || iv.Length == 0)
                throw new ArgumentNullException(nameof(iv));
            RijndaelManaged rijndaelManaged1 = null;
            string end;
            try
            {
                var rijndaelManaged2 = new RijndaelManaged();
                rijndaelManaged2.Mode = CipherMode.CBC;
                rijndaelManaged2.KeySize = 256;
                rijndaelManaged2.BlockSize = 128;
                rijndaelManaged2.Key = key;
                rijndaelManaged2.IV = iv;
                rijndaelManaged1 = rijndaelManaged2;
                var decryptor = rijndaelManaged1.CreateDecryptor(rijndaelManaged1.Key, rijndaelManaged1.IV);
                using (var memoryStream = new MemoryStream(cipherText))
                {
                    using (var cryptoStream = new CryptoStream(memoryStream, decryptor, CryptoStreamMode.Read))
                    {
                        using (var streamReader = new StreamReader(cryptoStream))
                        {
                            end = streamReader.ReadToEnd();
                            streamReader.Close();
                        }
                    }
                }
            }
            finally
            {
                rijndaelManaged1?.Clear();
            }
            return end;
        }
    }
}