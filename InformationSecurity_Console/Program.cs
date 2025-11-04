namespace InformationSecurity_Console;

internal static class Program
{
    private static void Main()
    {
        byte[] data1 = [0x11, 0x22, 0x33, 0x04];
        var data2 = data1.AsSpan();

        PrintBinary(data1);
        ShiftLeft28Bit(data2, 1);
        PrintBinary(data1);
    }

    private static void PrintBinary(byte[] data)
    {
        var binary = string.Join(" ", data.Select(b => Convert.ToString(b, 2).PadLeft(8, '0')));
        Console.WriteLine(binary);
    }

    private static void ShiftLeft28Bit(Span<byte> span, int k)
    {
        if (span.Length < 4)
            throw new ArgumentException("Span должен содержать хотя бы 4 байта");

        // Читаем 4 байта как 32-битное целое (little-endian)
        var value = BitConverter.ToUInt32(span);

        // Ограничиваем 28 бит (обнуляем старшие 4)
        value &= 0x0FFFFFFF;

        // Сдвигаем и снова ограничиваем 28 бит
        value = (value << k) & 0x0FFFFFFF;

        // Записываем обратно
        BitConverter.TryWriteBytes(span, value);
    }
}