namespace OnionRouter.Cryptography.Abstractions;

public interface IAsymmetricEncryption
{
    byte[] Encrypt(byte[] data, byte[] publicKey);

    byte[] Decrypt(byte[] encryptedData, byte[] privateKey);
}