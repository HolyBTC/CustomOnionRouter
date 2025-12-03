using System.Security.Cryptography;
using OnionRouter.Cryptography.Abstractions;
using OnionRouter.Cryptography.Exceptions;
using OnionRouter.Helpers;

namespace OnionRouter.Cryptography;

public class AsymmetricEncryptionService : IAsymmetricEncryption
{
    public byte[] Encrypt(byte[] data, byte[] publicKey)
    {
        if (data.IsNullOrEmpty())
        {
            throw new OnionRouterEncryptionException("data is null or empty");
        }

        if (publicKey.IsNullOrEmpty())
        {
            throw new OnionRouterEncryptionException("public key is null or empty");
        }

        if (data!.Length > 200)
        {
            throw new OnionRouterEncryptionException("Data payload is more that 200 bytes");
        }

        using RSA rsa = RSA.Create();
        rsa.ImportRSAPublicKey(publicKey, out _);
        return rsa.Encrypt(data, RSAEncryptionPadding.OaepSHA256);
    }

    public byte[] Decrypt(byte[] encryptedData, byte[] privateKey)
    {
        if (encryptedData.IsNullOrEmpty())
        {
            throw new OnionRouterEncryptionException("encryptedData is null or empty");
        }

        if (privateKey.IsNullOrEmpty())
        {
            throw new OnionRouterEncryptionException("private key is null or empty");
        }

        using RSA rsa = RSA.Create();
        rsa.ImportPkcs8PrivateKey(privateKey, out _);
        return rsa.Decrypt(encryptedData, RSAEncryptionPadding.OaepSHA256);
    }
}