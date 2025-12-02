using Crypto.SymmetricEncryption.Base;

namespace Crypto.SymmetricEncryption.Modes;

/// <summary>
/// Implements the Output Feedback (OFB) mode of operation for symmetric encryption.
/// Converts a block cipher into a synchronous stream cipher by repeatedly encrypting
/// the previous output (or IV for the first block) and XORing it with plaintext or ciphertext.
/// Encryption and decryption are identical operations.
/// </summary>
public class OFBMode :
    SymmetricModeBase
{
    /// <summary>
    /// Implements the Output Feedback (OFB) mode of operation for symmetric encryption.
    /// Converts a block cipher into a synchronous stream cipher by repeatedly encrypting
    /// the previous output (or IV for the first block) and XORing it with plaintext or ciphertext.
    /// Encryption and decryption are identical operations.
    /// </summary>
    public OFBMode(Action<Memory<byte>> encryptionFunc,
        Action<Memory<byte>> decryptionFunc,
        int blockSize,
        Memory<byte> initializationVector) : base(encryptionFunc,
        decryptionFunc,
        blockSize,
        initializationVector)
    {
        ThrowIfInitializationVectorIsNull();
    }

    /// <inheritdoc/>
    public override void Encrypt(Memory<byte> data)
    {
        ThrowIfIncorrectInputData(data);
        
        var iv =
            InitializationVector!
                .Value
                .ToArray();
        
        for (var i = 0; i < data.Length; i+=BlockSize)
        {
            EncryptionFunc(iv);
            
            var block = 
                data.Slice(i, BlockSize);
            
            for (var j = 0; j < BlockSize; ++j)
            {
                block.Span[j] ^= iv[j];
            }
        }
    }

    /// <inheritdoc/>
    public override void Decrypt(Memory<byte> data)
    {
        ThrowIfIncorrectInputData(data);
        Encrypt(data);
    }

    /// <inheritdoc/>
    public override async Task EncryptAsync(
        Memory<byte> data, 
        CancellationToken cancellationToken = default)
    {
        ThrowIfIncorrectInputData(data);
        await Task.Run(() => Encrypt(data), cancellationToken);
    }

    /// <inheritdoc/>
    public override async Task DecryptAsync(
        Memory<byte> data, 
        CancellationToken cancellationToken = default)
    {
        ThrowIfIncorrectInputData(data);
        await Task.Run(() => Decrypt(data), cancellationToken);
    }
}