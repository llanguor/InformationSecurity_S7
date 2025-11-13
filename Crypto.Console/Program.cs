using System.Numerics;
using System.Text;

namespace Crypto.Console;

internal static class Program
{
    private static readonly byte [] InitializationVector = 
    [
        0b11111111, 0b11111111, 0b11111111, 0b11111111,
        0b00000000, 0b00000000, 0b00000000, 0b00000000
    ];
    
    private static void Main()
    {
        var span = InitializationVector.AsSpan(
            InitializationVector.Length/2, 
            InitializationVector.Length/2);
        var value =
            new BigInteger(span, isUnsigned: true, isBigEndian: true) ;

        if ((value & 1)==0)
            value += 1;
        
        System.Console.WriteLine(value);
        System.Console.WriteLine(BinaryToString(InitializationVector));
        System.Console.WriteLine(BinaryToString(value.ToByteArray()));
    }
    
    public static string BinaryToString(byte[][] keys)
    {
        var builder = new StringBuilder();
        
        foreach (var key in keys)
        {
            foreach (var b in key)
            {
                builder.Append(
                    Convert.ToString(b, 2)
                        .PadLeft(8, '0') + " ");
            }
            builder.Append('\n');
        }
        
        return builder.ToString();
    }

    private static string BinaryToString(Span<byte> data)
    {
        var builder = new StringBuilder();
        
        foreach (var b in data)
        {
            for (var bit = 7; bit >= 0; bit--)
            {
                var result = ((b >> bit) & 1) == 1 ? '1' : '0';
                builder.Append(result);
            }
            builder.Append(' ');
        }
        
        builder.Append('\n');
        return builder.ToString();
    }
}