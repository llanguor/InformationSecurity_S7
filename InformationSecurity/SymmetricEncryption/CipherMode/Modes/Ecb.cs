using InformationSecurity.SymmetricEncryption.Base;
using InformationSecurity.SymmetricEncryption.CipherMode.Base;
namespace InformationSecurity.SymmetricEncryption.CipherMode.Modes;

public sealed class Ecb : CipherModeBase
{
    public override void Encrypt(Span<byte> data, IEncryption encryption, int blockSize)
    {
        for (var i = 0; i < data.Length; i += 8)
        {
            encryption.Encrypt(
                data.Slice(i, 8));
        }
    }

    public override void Decrypt(Span<byte> data, IEncryption encryption, int blockSize)
    {
        for (var i = 0; i < data.Length; i += 8)
        {
            var msg = data.Slice(i, 8);
            encryption.Encrypt(msg);
        }
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