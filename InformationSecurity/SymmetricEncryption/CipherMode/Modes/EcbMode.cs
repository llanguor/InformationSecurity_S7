using InformationSecurity.SymmetricEncryption.Base;
using InformationSecurity.SymmetricEncryption.CipherMode.Base;
namespace InformationSecurity.SymmetricEncryption.CipherMode.Modes;

public sealed class EcbMode(
    Action<Memory<byte>> encryptionFunc,
    int blockSize)
    : CipherModeBase(
        encryptionFunc,
        blockSize)
{
    public override void Encrypt(Memory<byte> data)
    {
        for (var i = 0; i < data.Length; i += BlockSize)
        {
            EncryptionFunc(
                data.Slice(i, BlockSize));
        }
    }

    public override void Decrypt(Memory<byte> data)
    {
        for (var i = 0; i < data.Length; i += BlockSize)
        {
            EncryptionFunc(
                data.Slice(i, BlockSize));
        }
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