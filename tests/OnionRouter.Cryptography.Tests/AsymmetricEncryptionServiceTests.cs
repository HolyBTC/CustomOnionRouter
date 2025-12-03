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

    // [Theory]
    // [InlineData("1234567891234567", "just random text 1", "Si7Fh9z405Jl85BybwZBVWw0N4peYyUf+jSIIlhk44I=")] // 128-bit key
    // [InlineData("12345678912345671234567891234567", "just random text 1", "5oteI5e5EeYYh5MJsrNOBlYzTuFDOcTcPGSCxwdO/u4=")] // 256-bit key
    // [InlineData("1234577891234561", "123 random", "3hbZscacLKYk1HKB/79Usg==")] // 128-bit key
    // [InlineData("12345778912345611234577891234561", "123 random", "NOcslQKwPaAEUkVA8Qn1Sg==")] // 256-bit key
    // [InlineData("1234562891234567", "just random text 1", "PBpk+zk168evNGSXj+dPMx/fax5Is0orikgcx6n24XE=")] // 128-bit key
    // [InlineData("12345628912345671234562891234567", "just random text 1", "Sth2eXpM6eOEB0zHCj/hsHRUUduK286hqR2HBDMdlJI=")] // 256-bit key
    // [InlineData("1234111891234567", "just random text 1", "XrjKFopZqXAKsF2cwJ53yskLFn4JIUhGT4m5prY4JnY=")] // 128-bit key
    // [InlineData("12341118912345671234111891234567", "just random text 1", "r2n1/DvdOSY+nyMCVk4BlKqXaMDiWPd4p3iEr3Mjc68=")] // 256-bit key
    // public void Encrypt_EncryptsCorrectly(string publicKey, string privateKey, string plainText, string expectedEncryptedDataAsBase64)
    // {
    //     // Act
    //     byte[] returnedBytes = _asymmetricEncryptionService.Encrypt(Encoding.UTF8.GetBytes(plainText), Convert.FromBase64String(publicKey));
    //     byte[] decryptedBytes = _asymmetricEncryptionService.Decrypt(returnedBytes, Convert.FromBase64String(privateKey));
    //
    //     // Assert
    //     returnedBytes.Should().NotBeNull();
    //     returnedBytes.Should().BeEquivalentTo(Convert.FromBase64String(expectedEncryptedDataAsBase64));
    //     decryptedBytes.Should().BeEquivalentTo(Encoding.UTF8.GetBytes(plainText));
    // }

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