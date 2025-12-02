using System.Security.Cryptography;
using OnionRouter.Cryptography.Abstractions;
using OnionRouter.Helpers;

namespace OnionRouter.Cryptography;

public class EncryptionService : IEncryptionService
{
    public byte[]? Encrypt(byte[]? plainData, byte[] encryptionKey)
    {
        // Check for empty or null plain text
        if (plainData.IsNullOrEmpty())
        {
            return null;
        }

        using Aes aesAlg = Aes.Create();

        aesAlg.Key = encryptionKey;

        aesAlg.Mode = CipherMode.ECB; 
        aesAlg.Padding = PaddingMode.PKCS7;

        // No IV generation or setting is required for ECB mode.
        ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV); // IV is internally ignored/zeroed

        // Create the streams used for encryption
        using MemoryStream msEncrypt = new MemoryStream();
        using CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write);
        using StreamWriter swEncrypt = new StreamWriter(csEncrypt);

        // Write all data to the stream
        swEncrypt.Write(plainData);

        // Return the Ciphertext as a Base64 string
        return msEncrypt.ToArray();
    }
}