using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

public class AesEncryption
{
    private static byte[] GenerateKeyAndIV(string salt)
    {
        byte[] iv = Encoding.UTF8.GetBytes(salt.PadRight(16, '\0').Substring(0, 16));
        return iv;
    }

    public static string Encrypt(string text, string saltt)
    {
        byte[] salt = GenerateKeyAndIV(saltt);

        byte[] encrypted;

        using (var aes = new RijndaelManaged())
        {
            aes.Key = salt;
            aes.IV = salt;
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;

            using (var encryptor = aes.CreateEncryptor(aes.Key, aes.IV))
            {
                using (var ms = new MemoryStream())
                {
                    using (var cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                    using (var sw = new StreamWriter(cs, Encoding.UTF8))
                    {
                        sw.Write(text);
                    }
                    encrypted = ms.ToArray();
                }
            }
        }

        return Convert.ToBase64String(encrypted);
    }

    public static string Decrypt(string cipherText, string saltt)
    {
        try
        {
            byte[] salt = GenerateKeyAndIV(saltt);

            byte[] cipherBytes = Convert.FromBase64String(cipherText);
            string plaintext = null;

            using (var aes = new RijndaelManaged())
            {
                aes.Key = salt;
                aes.IV = salt;
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;

                using (var decryptor = aes.CreateDecryptor(aes.Key, aes.IV))
                {
                    using (var ms = new MemoryStream(cipherBytes))
                    {
                        using (var cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
                        using (var sr = new StreamReader(cs, Encoding.UTF8))
                        {
                            plaintext = sr.ReadToEnd();
                        }
                    }
                }
            }
            return plaintext;
        }
        catch (Exception ex)
        {
            return null;
        }
    }
}
