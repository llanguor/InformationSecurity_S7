using System.Drawing;
using System.Dynamic;
using Crypto.SymmetricEncryption.Base.Interfaces;
using Microsoft.Extensions.Caching.Memory;

namespace Crypto.SymmetricEncryption.Base;

public abstract class KeyScheduleBase(int cacheSize) :
    IKeySchedule
{
    #region Fields
    
    private readonly IMemoryCache _cache = new MemoryCache(
        new MemoryCacheOptions()
        {
            SizeLimit = cacheSize
        });

    #endregion
    
    
    #region Constructors
    
    protected KeyScheduleBase() :
        this(1024)
    {
    }
    
    #endregion
    
    
    #region Methods
    
    /// <summary>
    /// Expands the input key into a full key schedule for encryption.
    /// Uses MemoryCache to store schedules. The input byte array is converted to Base64 
    /// to form a cache key.
    /// </summary>
    /// <param name="key">The input key as a byte array.</param>
    /// <returns>The full key schedule as a two-dimensional byte array.</returns>
    public byte[][] Expand(ReadOnlySpan<byte> key)
    {
        var cachedKey = Convert.ToBase64String(key);
        if (_cache.TryGetValue(cachedKey, out byte[][]? schedule))
        {
            return schedule!;
        }
        
        schedule = GenerateSchedule(key);
        _cache.Set(
            cachedKey, 
            schedule, 
            new MemoryCacheEntryOptions()
            {
                Size = 1
            });

        return schedule;
    }

    /// <summary>
    /// Generates the full key schedule for a specific encryption algorithm.
    /// This method must be overridden in derived classes to implement the 
    /// algorithm-specific key expansion procedure.
    /// </summary>
    /// <param name="key">The input key as a byte array.</param>
    /// <returns>The full key schedule as a two-dimensional byte array.</returns>
    protected abstract byte[][] GenerateSchedule(
        ReadOnlySpan<byte> key);
    
    #endregion

}