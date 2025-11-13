namespace Crypto.SymmetricEncryption.CipherPaddings.Base;

public abstract class CipherPaddingBase (
    int blockSize)
    : ICipherPadding
{
    protected int BlockSize { get; } = blockSize;
    
    public abstract byte[] Apply(byte[] data);

    public abstract byte[] Remove(byte[] data);
}