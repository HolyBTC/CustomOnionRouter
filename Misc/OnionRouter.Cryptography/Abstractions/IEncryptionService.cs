namespace OnionRouter.Cryptography.Abstractions;

public interface IEncryptionService
{
    byte[] Encrypt(byte[] plainBytes, byte[] encryptionKey);
}