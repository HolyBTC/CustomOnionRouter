using System.Security.Cryptography;
using OnionRouter.Cryptography.Abstractions;
using OnionRouter.Cryptography.Exceptions;
using OnionRouter.Helpers;

namespace OnionRouter.Cryptography;

public class EncryptionService : IEncryptionService
{
    public byte[] Encrypt(byte[] plainData, byte[] encryptionKey)
    {
        // Check for empty or null plain text
        if (plainData.IsNullOrEmpty())
        {
            throw new OnionRouterEncryptionException("Plain data is null or empty");
        }

        if (encryptionKey.IsNullOrEmpty())
        {
            throw new OnionRouterEncryptionException("Encryption key is null or empty");
        }

        using Aes aesAlg = Aes.Create();

        aesAlg.Key = encryptionKey;

        aesAlg.Mode = CipherMode.ECB; 
        aesAlg.Padding = PaddingMode.PKCS7;

        // No IV generation or setting is required for ECB mode. (ECB mode is actual basic Aes algorithm without
        // initialization vector)
        ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV); // IV is internally ignored/zeroed

        // Create the streams used for encryption
        using MemoryStream msEncrypt = new MemoryStream();
        using CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write);
        csEncrypt.Write(plainData, 0, plainData.Length);
        csEncrypt.FlushFinalBlock();

        // Return the Ciphertext as a Base64 string
        return msEncrypt.ToArray();
    }

    public byte[] Decrypt(byte[] encryptedData, byte[] encryptionKey)
    {
        if (encryptedData.IsNullOrEmpty())
        {
            throw new OnionRouterEncryptionException("encryptedData is null or empty");
        }

        if (encryptionKey.IsNullOrEmpty())
        {
            throw new OnionRouterEncryptionException("Encryption key is null or empty");
        }

        using Aes aesAlg = Aes.Create();

        aesAlg.Key = encryptionKey;

        aesAlg.Mode = CipherMode.ECB; 
        aesAlg.Padding = PaddingMode.PKCS7;

        // No IV generation or setting is required for ECB mode. (ECB mode is actual basic Aes algorithm without
        // initialization vector)
        ICryptoTransform encryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV); // IV is internally ignored/zeroed

        // Create the streams used for encryption
        using MemoryStream msEncrypt = new MemoryStream();
        using CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write);
        csEncrypt.Write(encryptedData, 0, encryptedData.Length);
        csEncrypt.FlushFinalBlock();

        // Return the Ciphertext as a Base64 string
        return msEncrypt.ToArray();
    }
}