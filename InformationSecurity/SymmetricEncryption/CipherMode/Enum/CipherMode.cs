namespace InformationSecurity.SymmetricEncryption.CipherMode.Enum;

/// <summary>
/// Defines the supported block cipher modes for symmetric encryption.
/// </summary>
public enum CipherMode
{
    Ecb = 0, 
    Cbc = 1, 
    Pcbc = 2, 
    Cfb = 3, 
    Ofb = 4, 
    Ctr = 5, 
    RandomDelta = 6
}