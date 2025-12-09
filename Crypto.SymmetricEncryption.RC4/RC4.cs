using Crypto.Core.Base.Interfaces;

namespace Crypto.SymmetricEncryption;

public sealed partial class RC4 :
    IEncryptionAlgorithm
{
    #region Fields

    private readonly KeySchedule _keySchedule;

    private readonly PseudoRandomGenerationAlgorithm _prga;

    private readonly RC4State _state = new();

    private readonly byte[] _key;
    
    #endregion
    
    
    #region Constructors

    public RC4(byte[] key)
    {
        _key = key;
        _prga = new PseudoRandomGenerationAlgorithm(_state);
        _keySchedule = new KeySchedule(_state);
        _keySchedule.Expand(key);
    }
    
    #endregion
    
    
    #region Methods
    
    public void Reset()
    {
        _state.I = 0;
        _state.J = 0;
        _keySchedule.Expand(_key);
    }
    
    public Memory<byte> Encrypt(
        Memory<byte> data)
    {
        ArgumentNullException.ThrowIfNull(data);
        
        if (data.Length == 0)
            return data;
        
        var span = data.Span;
        
        for (var i = 0; i < data.Length; ++i)
        {
            span[i] ^= _prga.GetNextByte(_state.SBox);
        }

        return data;
    }

    public Memory<byte> Decrypt(
        Memory<byte> data)
    {
        return Encrypt(data);
    }

    public void Encrypt(
        byte[] data,
        out byte[] result)
    {
        ArgumentNullException.ThrowIfNull(data);
        
        if (data.Length == 0)
            result = data;
        
        result = new byte[data.Length];
        
        for (var i = 0; i < data.Length; ++i)
        {
            result[i] = (byte)(
                data[i] ^ 
                _prga.GetNextByte(_state.SBox));
        }
    }

    public void Decrypt(
        byte[] data,
        out byte[] result)
    {
        Encrypt(data, out result);
    }

    public void Encrypt(
        string inputFilePath, 
        string outputFilePath)
    {
        if (string.IsNullOrWhiteSpace(inputFilePath))
            throw new ArgumentException("Input file path cannot be null or empty.", nameof(inputFilePath));
        
        var buffer = new byte[1];

        using var inputStream = 
            new FileStream(inputFilePath, FileMode.Open, FileAccess.Read);
        using var outputStream = 
            new FileStream(outputFilePath, FileMode.Create, FileAccess.Write);
    
        while (inputStream.Read(buffer) > 0)
        {
            buffer[0] ^= _prga.GetNextByte(_state.SBox);
            
            outputStream.Write(
                buffer, 
                0, 
                1);
        }
    }

    public void Decrypt(
        string inputFilePath, 
        string outputFilePath)
    {
        Encrypt(inputFilePath, outputFilePath);
    }

    public async Task<byte[]> EncryptAsync(
        byte[] data,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(data);

        if (data.Length == 0)
            return data;

        await Parallel.ForAsync(
            0,
            data.Length, 
            cancellationToken,
            (i, token) =>
            {
                token.ThrowIfCancellationRequested();
                
                data[i] ^= _prga.GetNextByte(
                    _state.SBox);
                
                return ValueTask.CompletedTask;
            });
        
        return data;
    }

    public async Task<byte[]> DecryptAsync(
        byte[] data,
        CancellationToken cancellationToken = default)
    {
        return await EncryptAsync(data, cancellationToken);
    }

    public async Task EncryptAsync(
        string inputFilePath,
        string outputFilePath,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(inputFilePath))
            throw new ArgumentException("Input file path cannot be null or empty.", nameof(inputFilePath));
        
        var buffer = new byte[1];

        await using var inputStream = 
            new FileStream(inputFilePath, FileMode.Open, FileAccess.Read);
        await using var outputStream = 
            new FileStream(outputFilePath, FileMode.Create, FileAccess.Write);
    
        while (await inputStream.ReadAsync(buffer, cancellationToken) > 0)
        {
            buffer[0] ^= _prga.GetNextByte(_state.SBox);
            
             await outputStream.WriteAsync(
                 buffer.AsMemory(0, 1), 
                 cancellationToken);
        }
    }

    public async Task DecryptAsync(
        string inputFilePath,
        string outputFilePath,
        CancellationToken cancellationToken = default)
    {
        await EncryptAsync(inputFilePath, outputFilePath, cancellationToken);
    }
    
    #endregion
}