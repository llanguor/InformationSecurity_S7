using System.Runtime.InteropServices;
using Crypto.SymmetricEncryption.Base;

namespace Crypto.SymmetricEncryption;

public sealed class DEALKeySchedule(
    DES des, 
    DEAL.DealKeySize dealKeySize,
    byte[] keyForSchedule)
    : KeyScheduleBase
{
    
    protected override byte[][] GenerateSchedule(Memory<byte> key)
    {
        des.Key = keyForSchedule;
        
        var masterKeys = new Memory<byte>[key.Length / 8];
        for (var i = 0; i < key.Length / 8; i++)
        {
            masterKeys[i] = key.Slice(i * 8, 8);
        }

        switch (dealKeySize)
        {
            case DEAL.DealKeySize.Key128:
            {
                var roundKeys = new byte[6][];
                des.EncryptBlock(
                    roundKeys[0] = masterKeys[0].ToArray());
                des.EncryptBlock(
                    roundKeys[1] = Xor(masterKeys[1], roundKeys[0]));
                des.EncryptBlock(
                    roundKeys[2] = Xor(masterKeys[0], roundKeys[1], 1));
                des.EncryptBlock(
                    roundKeys[3] = Xor(masterKeys[1], roundKeys[2], 2));
                des.EncryptBlock(
                    roundKeys[4] = Xor(masterKeys[0], roundKeys[3], 4));
                des.EncryptBlock(
                    roundKeys[5] = Xor(masterKeys[1], roundKeys[4], 8));
                return roundKeys;
            }
            case DEAL.DealKeySize.Key192:
            {
                var roundKeys = new byte[6][];
                des.EncryptBlock(
                    roundKeys[0] = masterKeys[0].ToArray());
                des.EncryptBlock(
                    roundKeys[1] = Xor(masterKeys[1], roundKeys[0]));
                des.EncryptBlock(
                    roundKeys[2] = Xor(masterKeys[2], roundKeys[1]));
                des.EncryptBlock(
                    roundKeys[3] = Xor(masterKeys[0], roundKeys[2], 1));
                des.EncryptBlock(
                    roundKeys[4] = Xor(masterKeys[1], roundKeys[3], 2));
                des.EncryptBlock(
                    roundKeys[5] = Xor(masterKeys[2], roundKeys[4], 4));
                return roundKeys;
            }
            case DEAL.DealKeySize.Key256:
            {
                var roundKeys = new byte[8][];
                des.EncryptBlock(
                    roundKeys[0] = masterKeys[0].ToArray());
                des.EncryptBlock(
                    roundKeys[1] = Xor(masterKeys[1], roundKeys[0]));
                des.EncryptBlock(
                    roundKeys[2] = Xor(masterKeys[2], roundKeys[1]));
                des.EncryptBlock(
                    roundKeys[3] = Xor(masterKeys[3], roundKeys[2]));
                des.EncryptBlock(
                    roundKeys[4] = Xor(masterKeys[0], roundKeys[3], 1));
                des.EncryptBlock(
                    roundKeys[5] = Xor(masterKeys[1], roundKeys[4], 2));
                des.EncryptBlock(
                    roundKeys[6] = Xor(masterKeys[2], roundKeys[5], 4));
                des.EncryptBlock(
                    roundKeys[7] = Xor(masterKeys[3], roundKeys[6], 8));
                return roundKeys;
            }
            default:
                throw new ArgumentException(
                    $"Invalid key size: {key.Length} bytes. Expected 16, 24, or 32 bytes.");
        }
    }

    private static byte[] Xor(
        Memory<byte> left,
        Memory<byte> right)
    {
        var result = left.ToArray();
        MemoryMarshal.AsRef<ulong>(result) =
            MemoryMarshal.AsRef<ulong>(left.Span) ^
            MemoryMarshal.AsRef<ulong>(right.Span);
        return result;
    }
    
    private static byte[] Xor(
        Memory<byte> left,
        Memory<byte> right,
        ulong mask)
    {
        var result = left.ToArray();
        MemoryMarshal.AsRef<ulong>(result) =
            MemoryMarshal.AsRef<ulong>(left.Span) ^
            MemoryMarshal.AsRef<ulong>(right.Span) ^
            mask;
        return result;
    }
}