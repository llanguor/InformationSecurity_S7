using System.Drawing;
using System.Dynamic;
using Crypto.SymmetricEncryption.Base.Interfaces;
using Microsoft.Extensions.Caching.Memory;

namespace Crypto.SymmetricEncryption.Base;

/// <summary>
/// Base class for key schedule implementations in symmetric encryption algorithms.
/// Provides caching of expanded keys and defines an abstract method for generating
/// algorithm-specific key schedules.
/// </summary>
public abstract class KeyScheduleBase :
    IKeySchedule
{
    #region Fields
    
    private readonly IMemoryCache _cache;

    #endregion
    
    
    #region Constructors
    
    /// <summary>
    /// Initializes a new instance of the <see cref="KeyScheduleBase"/> class
    /// with a default cache size of 1024 entries.
    /// </summary>
    protected KeyScheduleBase() :
        this(1024)
    {
    }
    
    /// <summary>
    /// Base class for key schedule implementations in symmetric encryption algorithms.
    /// Provides caching of expanded keys and defines an abstract method for generating
    /// algorithm-specific key schedules.
    /// </summary>
    /// <param name="cacheSize">The maximum number of key schedules to cache in memory.</param>
    protected KeyScheduleBase(int cacheSize)
    {
        if (cacheSize <= 0)
            throw new ArgumentOutOfRangeException(nameof(cacheSize), "Cache size must be positive.");
        
        _cache = new MemoryCache(
            new MemoryCacheOptions()
            {
                SizeLimit = cacheSize
            });
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
    public byte[][] Expand(Memory<byte> key)
    {
        if (key.IsEmpty)
            throw new ArgumentException("Key cannot be empty.", nameof(key));
        
        var cachedKey = Convert.ToBase64String(key.Span);
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
    protected abstract byte[][] GenerateSchedule(Memory<byte> key);
    
    #endregion

}