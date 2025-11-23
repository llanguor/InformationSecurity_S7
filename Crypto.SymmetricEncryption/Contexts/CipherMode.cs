namespace Crypto.SymmetricEncryption.Contexts;

    
/// <summary>
/// Defines the supported block cipher modes for symmetric encryption.
/// </summary>
public enum CipherMode
{
    ECB = 0, 
    CBC = 1, 
    PCBC = 2, 
    CFB = 3, 
    OFB = 4, 
    CTR = 5, 
    RandomDelta = 6
}