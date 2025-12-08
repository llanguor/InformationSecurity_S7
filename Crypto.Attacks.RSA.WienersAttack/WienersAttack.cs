using System.Numerics;
using Crypto.Attacks.RSA.Core;

namespace Crypto.Attack.RSA;

public class WienersAttack : 
    IRSAAttack
{
    private readonly MathService _mathService = new(); 
    
    public BigInteger Perform(AsymmetricEncryption.RSA.RSAKey publicKey)
    {
         var convergents = 
             _mathService.GetConvergentsFractions(
                 publicKey.Exponent, 
                 publicKey.Modulus);

         for (var i = 2; i < convergents.Length; ++i)
         {
             var fi = 
                 (publicKey.Exponent * convergents[i].Item2 - 1) / 
                 convergents[i].Item1;
             
             //If roots is not integer values, returns empty array
             var roots = 
                 _mathService.SolveQuadraticForWienersAttack(
                     1, 
                     fi - publicKey.Modulus - 1,
                     publicKey.Modulus);
             
             if (roots.Length == 2)
             {
                 return convergents[i].Item2;
             }
         }
         
         throw new InvalidOperationException("Decryption exponent not found.");
    }
}