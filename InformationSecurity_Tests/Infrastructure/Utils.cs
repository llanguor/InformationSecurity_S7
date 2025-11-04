using System.Text;

namespace InformationSecurity_Tests.Infrastructure;

public static class Utils
{
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
    
    public static string BinaryToString(Span<byte> data)
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
    
    public static string BinaryToString(ulong value)
    {
        var builder = new StringBuilder();
        
        for (var byteIndex = 7; byteIndex >= 0; byteIndex--)
        {
            var b = (byte)((value >> (byteIndex * 8)) & 0xFF);
            
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