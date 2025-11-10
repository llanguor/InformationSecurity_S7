using InformationSecurity.SymmetricEncryption.Base;
using InformationSecurity.SymmetricEncryption.CipherMode.Base;
namespace InformationSecurity.SymmetricEncryption.CipherMode.Modes;

public sealed class Cfb(
    byte[] initializationVector)
    : CipherModeBase(initializationVector)
{
    public override void Encrypt(Span<byte> data, IEncryption encryption, int blockSize)
    {
        throw new NotImplementedException();
    }

    public override void Decrypt(Span<byte> data, IEncryption encryption, int blockSize)
    {
        throw new NotImplementedException();
    }

    public override async Task EncryptAsync(Memory<byte> data, IEncryption encryption, int blockSize)
    {
        throw new NotImplementedException();
    }

    public override async Task DecryptAsync(Memory<byte> data, IEncryption encryption, int blockSize)
    {
        throw new NotImplementedException();
    }
}