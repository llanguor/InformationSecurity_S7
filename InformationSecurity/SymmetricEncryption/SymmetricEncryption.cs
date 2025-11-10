namespace InformationSecurity.SymmetricEncryption;
using Base;

public sealed class SymmetricEncryption(
    IEncryption encryptionAlgorithm,
    int blockSize,
    byte[] key, 
    CipherMode.Enum.CipherMode mode, 
    CipherPadding.Enum.CipherPadding padding, 
    byte[]? initializationVector = null, 
    params object[] parameters) 
    : SymmetricEncryptionBase(encryptionAlgorithm, blockSize, key, mode, padding, initializationVector, parameters)
{
    /// <inheritdoc/>
    public override void Encrypt(Span<byte> data)
    {
        CipherPaddingContext.ApplyPadding(data, BlockSize);
        CipherModeContext.Encrypt(data, Encryption, BlockSize);
        //ИЛИ МБ ЛУЧШЕ ЗАСУНУТЬ В КОНСТРУКТОР BlockSize у этой фигни
        //ВОЗМОЖНО: поменять всё на наследование?
        
        //Биты контроля четности делаются ДО входа в алгоритм. В самом тесте
        
        //1. На вход получаем большой блок произвольного размера.
        //   Если он не кратен 64, то делаем набивки
        //2. Делаем из него много Span-ов по 64 бита
        //3. Обрабатываем эти Span-ы в цикле
        //4. В зависимости от режима, по-разному xor
        //5. Возвращаем ответ
        
        // Как делать:
        // 1. Делаем набивки
        //    Где делать? В отдельном методе?
        // 2. Обрабатываем все по режимам.
        //    Где делать? В отдельном классе? Паттерн "стратегия"?
        // 3. 
        
        //Предполагаем, что к этому моменту во входных данных
        //имеются биты контроля четности и всё это кратно 8
 

    }

    /// <inheritdoc/>
    public override void Encrypt(byte[] data, out byte[] result)
    {
        throw new NotImplementedException();
    }

    /// <inheritdoc/>
    public override void Encrypt(string inputFilePath, string outputFilePath)
    {
        throw new NotImplementedException();
    }
    
    /// <inheritdoc/>
    public override void Decrypt(Span<byte> data)
    {
        throw new NotImplementedException();
    }

    /// <inheritdoc/>
    public override void Decrypt(byte[] data, out byte[] result)
    {
        throw new NotImplementedException();
    }

    /// <inheritdoc/>
    public override void Decrypt(string inputFilePath, string outputFilePath)
    {
        throw new NotImplementedException();
    }

    /// <inheritdoc/>
    public override async Task<byte[]> EncryptAsync(byte[] data)
    {
        throw new NotImplementedException();
    }

    /// <inheritdoc/>
    public override async Task EncryptAsync(string inputFilePath, string outputFilePath)
    {
        throw new NotImplementedException();
    }
    
    /// <inheritdoc/>
    public override async Task<byte[]> DecryptAsync(byte[] data)
    {
        throw new NotImplementedException();
    }

    /// <inheritdoc/>
    public override async Task DecryptAsync(string inputFilePath, string outputFilePath)
    {
        throw new NotImplementedException();
    }
}