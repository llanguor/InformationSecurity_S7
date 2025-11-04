using Serilog;

namespace InformationSecurity_Tests.Infrastructure;

public static class Logger
{
    private static Serilog.Core.Logger? _logger;

    public static Serilog.ILogger GetInstance()
    {
        if (_logger != null) 
            return _logger;

        _logger = new LoggerConfiguration()
            .MinimumLevel.Debug()
            .Enrich.FromLogContext()
            .WriteTo.Console(
                outputTemplate: "[{Timestamp:HH:mm:ss} {Level:u3}] {Message:lj}{NewLine}{Exception}")
            .WriteTo.File(
                "logs/log.txt",
                outputTemplate: "[{Timestamp:yyyy-MM-dd HH:mm:ss} {Level:u3}] {Message:lj}{NewLine}{Exception}")
            .CreateLogger();

        Log.Logger = _logger;
        return _logger;
        
    }
}