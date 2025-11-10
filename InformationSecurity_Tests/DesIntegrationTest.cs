using DryIoc;
using InformationSecurity_Tests.Infrastructure;

namespace InformationSecurity_Tests;

public class DesIntegrationTest
{
    private Container? _container;
    
    [SetUp]
    public void Setup()
    {
        Logger.GetInstance();
        _container = new Container();
    }
    
    [TearDown]
    public void TearDown()
    {
        _container?.Dispose();
    }

}