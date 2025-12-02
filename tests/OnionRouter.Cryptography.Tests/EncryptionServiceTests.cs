using System.Text;
using FluentAssertions;

namespace OnionRouter.Cryptography.Tests;

public class EncryptionServiceTests
{
    private readonly EncryptionService _encryptionService = new();

    [Theory]
    [InlineData("1234567891234567", "just random text 1", "Si7Fh9z405Jl85BybwZBVWw0N4peYyUf+jSIIlhk44I=")] // 128-bit key
    [InlineData("12345678912345671234567891234567", "just random text 1", "5oteI5e5EeYYh5MJsrNOBlYzTuFDOcTcPGSCxwdO/u4=")] // 256-bit key
    [InlineData("1234577891234561", "123 random", "3hbZscacLKYk1HKB/79Usg==")] // 128-bit key
    [InlineData("12345778912345611234577891234561", "123 random", "NOcslQKwPaAEUkVA8Qn1Sg==")] // 256-bit key
    [InlineData("1234562891234567", "just random text 1", "PBpk+zk168evNGSXj+dPMx/fax5Is0orikgcx6n24XE=")] // 128-bit key
    [InlineData("12345628912345671234562891234567", "just random text 1", "Sth2eXpM6eOEB0zHCj/hsHRUUduK286hqR2HBDMdlJI=")] // 256-bit key
    [InlineData("1234111891234567", "just random text 1", "XrjKFopZqXAKsF2cwJ53yskLFn4JIUhGT4m5prY4JnY=")] // 128-bit key
    [InlineData("12341118912345671234111891234567", "just random text 1", "r2n1/DvdOSY+nyMCVk4BlKqXaMDiWPd4p3iEr3Mjc68=")] // 256-bit key
    public void Encrypt_EncryptsCorrectly(string encryptionKey, string plainText, string expectedEncryptedDataAsBase64)
    {
        // Act
        byte[]? returnedBytes = _encryptionService.Encrypt(Encoding.UTF8.GetBytes(plainText), Encoding.UTF8.GetBytes(encryptionKey));

        // Assert
        returnedBytes.Should().NotBeNull();
        returnedBytes.Should().BeEquivalentTo(Convert.FromBase64String(expectedEncryptedDataAsBase64));
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void Encrypt_WhenPassedNullOrEmpty_ReturnsNull(bool isArgumentNull)
    {
        // Act
        byte[]? returnedBytes = _encryptionService.Encrypt(isArgumentNull ? null : [], []);

        // Assert
        returnedBytes.Should().BeNull();
    }

    [Theory]
    [InlineData(5)]
    [InlineData(10)]
    [InlineData(15)]
    public void Encrypt_WhenSameKeyAndSameSizedText_ReturnsSameSizedEncryptedData(int length)
    {
        // Arrange
        string encryptionKey = "1234567891234567";

        // Act && Assert
        int? returnedLength = null;
        for (int i = 0; i < 100; i++)
        {
            byte[] encryptedData = _encryptionService.Encrypt(
                Encoding.UTF8.GetBytes(Guid.NewGuid().ToString()[..length]),
                Encoding.UTF8.GetBytes(encryptionKey))!;
            returnedLength ??= encryptedData.Length; // sets value only if 'returnedLength' is null
            returnedLength.Should().Be(encryptedData.Length);
        }
    }
}