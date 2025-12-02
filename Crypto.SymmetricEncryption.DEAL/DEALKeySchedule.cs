using System.Runtime.InteropServices;
using Crypto.SymmetricEncryption.Base;

namespace Crypto.SymmetricEncryption;

/// <summary>
/// Implements the DEAL block cipher.
/// </summary>
public sealed partial class DEAL
{
    /// <summary>
    /// Implements a key schedule for the DEAL cipher using DES.
    /// Generates round keys based on the specified DEAL key size (128, 192, 256 bits).
    /// </summary>
    /// <param name="des">DES instance used for block encryption.</param>
    /// <param name="dealKeySize">Specifies the DEAL key size for round key generation.</param>
    /// <param name="keyForSchedule">Initial key bytes used to derive round keys.</param>
    public sealed class DEALKeySchedule(
        DES des,
        DealKeySize dealKeySize,
        byte[] keyForSchedule)
        : KeyScheduleBase
    {

        /// <summary>
        /// Generates round keys for the DEAL cipher using DES and XOR operations.
        /// </summary>
        /// <param name="key">Memory of bytes representing the input key.</param>
        /// <returns>Jagged array of byte arrays containing the round keys.</returns>
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
                case DealKeySize.Key128:
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
                case DealKeySize.Key192:
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
                case DealKeySize.Key256:
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

        /// <summary>
        /// Performs bitwise XOR between two 8-byte blocks.
        /// </summary>
        /// <param name="left">First 8-byte block.</param>
        /// <param name="right">Second 8-byte block.</param>
        /// <returns>Resulting 8-byte block after XOR.</returns>
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

        /// <summary>
        /// Performs bitwise XOR between two 8-byte blocks and applies an additional mask.
        /// </summary>
        /// <param name="left">First 8-byte block.</param>
        /// <param name="right">Second 8-byte block.</param>
        /// <param name="mask">Mask to apply during XOR.</param>
        /// <returns>Resulting 8-byte block after XOR with mask.</returns>
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
}