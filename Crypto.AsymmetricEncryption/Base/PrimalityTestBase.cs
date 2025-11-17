using System.Numerics;
using Crypto.AsymmetricEncryption.Base.Interfaces;

namespace Crypto.AsymmetricEncryption.Base;

public abstract class PrimalityTestBase :
    IPrimalityTest
{
    //Шаблонный метод.
    //Общий метод нужен
    //другие методы задают конкретные шаги выполнения
    //они виртуальные или абстрактные и можно переопределить необходимые
    //что то должно быть абстрактным?
    
    public PrimalityResult IsPrimary(BigInteger value, double targetProbability)
    {
        throw new NotImplementedException();
    }
}