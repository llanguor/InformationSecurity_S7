using System.Numerics;
using Crypto.AsymmetricEncryption.Base;

namespace Crypto.AsymmetricEncryption.PrimalityTests;

public class FermatPrimalityTest() :
    PrimalityTestBase(0.5)
{
    private static readonly HashSet<BigInteger> CarmichaelNumbers =
    [
        561, 1105, 1729, 2465, 2821, 6601, 8911, 10585, 15841, 29341,
        41041, 46657, 52633, 62745, 63973, 75361, 101101, 115921, 126217,
        162401, 172081, 188461, 252601, 278545, 294409, 314821, 334153,
        340561, 399001, 410041, 449065, 488881, 512461, 530881, 552721,
        656601, 658801, 670033, 748657, 825265, 838201, 852841, 997633,
        1024651, 1033669, 1050985, 1058197, 1062341, 1078901, 1152271,
        1193221, 1461241, 1588261, 1615681, 1773289, 1857241, 1909001,
        1929601, 2056321, 2090881, 2113921, 2433601, 2455921, 2508017,
        2628073, 2704801, 2722501, 2785453, 2944091, 3148213, 3341537,
        3405611, 3990013, 4100413, 4490653, 4888813, 5124613, 5308813,
        5527213, 6566011, 6588013, 6700337, 7486571, 8252657, 8382013,
        8528417, 9976331, 10246513, 10336691, 10509853, 10581973, 10623413,
        10789013, 11522713, 11932213, 14612413, 15882613
    ];
    
    protected override bool ValidateCondition(BigInteger p, BigInteger a)
    {
        if (CarmichaelNumbers.Contains(p))
            return false; 
        
        return CryptoMathService.ModPow(
                a, 
                p - 1, 
                p) == 1;
    }
}