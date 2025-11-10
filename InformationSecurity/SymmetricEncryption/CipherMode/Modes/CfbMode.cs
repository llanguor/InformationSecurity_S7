using InformationSecurity.SymmetricEncryption.Base;
using InformationSecurity.SymmetricEncryption.CipherMode.Base;
namespace InformationSecurity.SymmetricEncryption.CipherMode.Modes;

public sealed class CfbMode(
    Action<Memory<byte>> encryptionFunc,
    int blockSize,
    byte[] initializationVector)
    : CipherModeBase(
        encryptionFunc,
        blockSize,
        initializationVector)
{
    public override void Encrypt(Memory<byte> data)
    {
        throw new NotImplementedException();
    }

    public override void Decrypt(Memory<byte> data)
    {
        throw new NotImplementedException();
    }

    public override async Task EncryptAsync(Memory<byte> data)
    {
        throw new NotImplementedException();
    }

    public override async Task DecryptAsync(Memory<byte> data)
    {
        throw new NotImplementedException();
    }
}