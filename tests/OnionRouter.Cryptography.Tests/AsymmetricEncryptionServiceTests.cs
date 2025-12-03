using System.Security.Cryptography;
using System.Text;
using FluentAssertions;
using OnionRouter.Cryptography.Exceptions;

namespace OnionRouter.Cryptography.Tests;

public class AsymmetricEncryptionServiceTests
{
    private readonly AsymmetricEncryptionService _asymmetricEncryptionService = new();

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void Encrypt_WhenPassedNullOrEmpty_ReturnsNull(bool isArgumentNull)
    {
        // Act
        OnionRouterEncryptionException ex =
            Assert.Throws<OnionRouterEncryptionException>(() =>
                _asymmetricEncryptionService.Encrypt((isArgumentNull ? null : [])!, [ 0x12 ]));

        // Assert
        ex.Message.Should().Be("data is null or empty");
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void Encrypt_WhenEmptyEncryptionKey_ThrowException(bool encryptionKeyIsNull)
    {
        // Act & Assert
        OnionRouterEncryptionException ex =
            Assert.Throws<OnionRouterEncryptionException>(() =>
                _asymmetricEncryptionService.Encrypt([ 0x12 ], (encryptionKeyIsNull ? null : [])!));

        ex.Message.Should().Be("public key is null or empty");
    }

    [Fact]
    public void Encrypt_WhenDataMoreThan200Bytes_ThrowException()
    {
        // Arrange
        byte[] data = new byte[201];
        byte[] publicKey = [ 0x12, 0x34, 0x56 ];

        // Act & Assert
        OnionRouterEncryptionException ex =
            Assert.Throws<OnionRouterEncryptionException>(() =>
                _asymmetricEncryptionService.Encrypt(data, publicKey));

        ex.Message.Should().Be("Data payload is more that 200 bytes");
    }

    [Theory]
    [InlineData(5)]
    [InlineData(10)]
    [InlineData(15)]
    [InlineData(20)]
    public void Encrypt_WhenSameKeyAndSameSizedText_ReturnsSameSizedEncryptedData(int length)
    {
        // Arrange
        using RSA rsa = RSA.Create(4096);
        byte[] publicKey = rsa.ExportRSAPublicKey();
        byte[] privateKey = rsa.ExportPkcs8PrivateKey();

        // Act && Assert
        int? returnedLength = null;
        for (int i = 0; i < 100; i++)
        {
            byte[] plainData = Encoding.UTF8.GetBytes(Guid.NewGuid().ToString()[..length]);
            byte[] encryptedData = _asymmetricEncryptionService.Encrypt(
                plainData,
                publicKey);
            returnedLength ??= encryptedData.Length; // sets value only if 'returnedLength' is null
            returnedLength.Should().Be(encryptedData.Length);

            // Additionally check if decryption works correctly
            byte[] decryptedData = _asymmetricEncryptionService.Decrypt(encryptedData, privateKey);
            decryptedData.Should().BeEquivalentTo(plainData);
        }
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void Decrypt_WhenPassedNullOrEmpty_ReturnsNull(bool isArgumentNull)
    {
        // Act
        OnionRouterEncryptionException ex =
            Assert.Throws<OnionRouterEncryptionException>(() =>
                _asymmetricEncryptionService.Decrypt((isArgumentNull ? null : [])!, [ 0x12 ]));

        // Assert
        ex.Message.Should().Be("encryptedData is null or empty");
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void Decrypt_WhenEmptyDecryptionKey_ThrowException(bool encryptionKeyIsNull)
    {
        // Act & Assert
        OnionRouterEncryptionException ex =
            Assert.Throws<OnionRouterEncryptionException>(() =>
                _asymmetricEncryptionService.Decrypt([ 0x12 ], (encryptionKeyIsNull ? null : [])!));

        ex.Message.Should().Be("private key is null or empty");
    }
}