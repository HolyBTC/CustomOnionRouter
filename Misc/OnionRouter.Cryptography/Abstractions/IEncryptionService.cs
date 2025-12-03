namespace OnionRouter.Cryptography.Abstractions;

public interface IEncryptionService
{
    byte[] Encrypt(byte[] plainBytes, byte[] encryptionKey);

    byte[] Decrypt(byte[] encryptedData, byte[] encryptionKey);
}