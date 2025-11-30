using System.Numerics;
using System.Reflection.PortableExecutable;
using System.Security.Cryptography;
using System.Text;

namespace Crypto.Console;

internal static class Program
{
    private static readonly byte [] Randomized = 
    [
        0b00000000, 0b00000000,0b00000000, 0b01111111, 0b10111111, 0b11011111,
        0b11101111, 0b11110111, 0b11111011, 0b11111101
    ];

    private static void Main()
    {
        var bi = new BigInteger(Randomized, true, true);
        System.Console.WriteLine(bi.ToString());
        
        var r = bi.ToByteArray(true, true);
        System.Console.WriteLine(BinaryToString(Randomized));
        System.Console.WriteLine(BinaryToString(r));
        
        /*
        var array0 = new byte[9];

        RandomNumberGenerator.Fill(array0);
        var value0 =
            new BigInteger(array0, isUnsigned: false, isBigEndian: false) ;
        System.Console.WriteLine(value0);
        RandomNumberGenerator.Fill(array0);
        System.Console.WriteLine(value0);


        var array1 = new byte[9];
        RandomNumberGenerator.Fill(array1.AsSpan(0, array1.Length - 1));
        array1[0] |= 0b00000001;
        //array1[^1] &= 0b00000000;
        array1[^2] = (byte)(array1[^2] & 0b00111111 | 0b10000000);

        var array2 = new byte[9];
        RandomNumberGenerator.Fill(array2.AsSpan(0, array1.Length - 1));
        array2[0] |= 0b00000001;

        array2[^2] = (byte)(array2[^2] & (0xFF >> 3) | (0xFF << (8-3) & 0b10100000));

        var value1 =
            new BigInteger(array1.AsSpan(), isUnsigned: false, isBigEndian: false) ;
        var value2 =
            new BigInteger(array2.AsSpan(), isUnsigned: false, isBigEndian: false) ;

        System.Console.WriteLine(value1);
        System.Console.WriteLine(value2);
        System.Console.WriteLine(BinaryToString(array1));
        System.Console.WriteLine(BinaryToString(array2));
        */
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