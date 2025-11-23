using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Crypto.Core;
using Crypto.SymmetricEncryption.Base.Interfaces;
using Crypto.SymmetricEncryption.Contexts;
using CipherMode = Crypto.SymmetricEncryption.Contexts.CipherMode;

namespace Crypto.SymmetricEncryption;

/// <summary>
/// Implements the Data Encryption Standard (Crypto.Core.DES) symmetric encryption algorithm.
/// This class provides functionality for encrypting and decrypting 64-bit blocks of data.
/// </summary>
public sealed class TripleDES : 
    SymmetricEncryption
{
    #region Enumerations
    
    /// <summary>
    /// Specifies the variant of the TripleDES (3DES) algorithm.
    /// </summary>
    public enum TripleDESType
    {
        /// <summary>
        /// Encrypt-Encrypt-Encrypt using three independent keys (K1, K2, K3).
        /// Provides full 3-key TripleDES security (168-bit effective).
        /// </summary>
        EEE3,

        /// <summary>
        /// Encrypt-Decrypt-Encrypt using three independent keys (K1, K2, K3).
        /// Standard and most commonly used 3DES construction (3-key EDE).
        /// </summary>
        EDE3
    }
    
    #endregion

    
    #region Fields
    
    private readonly DES _desEncryption;

    private readonly byte[][] _keys;
    
    private readonly TripleDESType _type;
    
    #endregion
    
    
    #region Constructors
    
    public TripleDES(
        byte[][] keys, 
        TripleDESType algorithmType,
        CipherPadding padding, 
        CipherMode mode, 
        byte[]? initializationVector = null, 
        params object[] parameters) : 
        base(8, 8, keys[0], padding, mode, initializationVector, parameters)
    {
        if (keys.Length != 3)
        {
            throw new ArgumentException("Key must be 3 or more.");
        }

        _type = algorithmType;
        
        _keys = keys;
        
        _desEncryption =
            new DES(
                keys[0],
                padding,
                mode);
    }
    
    #endregion
    

    #region Methods
    
    /// <inheritdoc/>
    internal override void EncryptBlock(Memory<byte> data)
    {
        _desEncryption.Key = _keys[0];
        _desEncryption.Encrypt(data);

        switch (_type)
        {
            case TripleDESType.EEE3:
                _desEncryption.Key = _keys[0];
                _desEncryption.Encrypt(data);
                break;
            case TripleDESType.EDE3:
                _desEncryption.Key = _keys[1];
                _desEncryption.Decrypt(data);
                break;
            default:
                throw new ArgumentOutOfRangeException();
        }
        
        _desEncryption.Key = _keys[2];
        _desEncryption.Encrypt(data);
    }

    /// <inheritdoc/>
    internal override void DecryptBlock(Memory<byte> data)
    {
        _desEncryption.Key = _keys[0];
        _desEncryption.Decrypt(data);
        
        switch (_type)
        {
            case TripleDESType.EEE3:
                _desEncryption.Key = _keys[1];
                _desEncryption.Decrypt(data);
                break;
            case TripleDESType.EDE3:
                _desEncryption.Key = _keys[1];
                _desEncryption.Encrypt(data);
                break;
            default:
                throw new ArgumentOutOfRangeException();
        }
        
        _desEncryption.Key = _keys[2];
        _desEncryption.Decrypt(data);
    }
    
    #endregion
}