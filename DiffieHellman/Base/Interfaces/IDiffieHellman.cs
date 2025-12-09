using System.Numerics;

namespace Crypto.KeyExchange.Base.Interfaces;

internal interface IDiffieHellman
{
    void GenerateKeyPair();
    
    void ComputeSharedSecret(BigInteger externalPublicKey);
}