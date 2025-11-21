using System.Numerics;
using Crypto.AsymmetricEncryption.Base;

namespace Crypto.AsymmetricEncryption.PrimalityTests;

public class MillerRabinPrimalityTest() :
    PrimalityTestBase(0.5)
{
    /*
     •	на каждой итерации не нужно заново возводить число в полную степень.
      У нас уже есть результат возведения с прошлой итерации. 
      Нужно лишь возвести в квадрат по модулю. 
      На следующей итерации еще раз возвести в квадрат по модулю.
       И так далее. Так экономим перфоманс
     */
    
    protected override bool ValidateCondition(BigInteger n, BigInteger a)
    {
        var s = 0;
        var d = n - 1;
        while ((d & 1) == 0)
        {
            d >>= 1; 
            ++s;
        }

        var powered =
            CryptoMathService.ModPow(a, d, n);
        if (powered == 1 || powered == n-1)
            return true;
        
        for (var i = 1; i <= s; ++i)
        {
            powered = (powered * powered) % n; 
            
            if (powered == n-1)
            {
                return true;
            }
        }

        return false;
    }
}