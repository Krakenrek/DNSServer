namespace DNS.Storage;

/// <summary>
/// Simple and abstract implementation of internal record storage.
/// Inheritors can be in-memory or use a DB.
/// </summary>
/// <typeparam name="TKey">Type of key.</typeparam>
/// <typeparam name="TRecord">Type of record.</typeparam>
public interface IDomainRecordHolder<in TKey, TRecord> where TKey : notnull
{
    /// <summary>
    /// Searches and retrieve read-only list of records connected to given key.
    /// </summary>
    /// <param name="key">Key to search.</param>
    IReadOnlyList<TRecord> this[TKey key] { get; }

    /// <summary>
    /// Adds given record to given key.
    /// </summary>
    /// <param name="key">Key to bound.</param>
    /// <param name="record">Value to add.</param>
    void Add(TKey key, TRecord record);
    
    /// <summary>
    /// Adds given records to given key.
    /// </summary>
    /// <param name="key">Key to bound.</param>
    /// <param name="records">Values to add.</param>
    void AddRange(TKey key, IEnumerable<TRecord> records);

    /// <summary>
    /// Delete stored data.
    /// </summary>
    void Clear();
}

/// <summary>
/// Simple implementation of in-memory storage.
/// </summary>
/// <typeparam name="TKey">Type of key.</typeparam>
/// <typeparam name="TRecord">Type of record.</typeparam>
public class SimpleRecordHolder<TKey, TRecord> : IDomainRecordHolder<TKey, TRecord> where TKey : notnull
{
    /// <summary>
    /// Underlying data structure.
    /// </summary>
    private Dictionary<TKey, List<TRecord>> Records { get; } = new();
    
    public IReadOnlyList<TRecord> this[TKey key] =>
        Records.TryGetValue(key, out var records)
            ? records.AsReadOnly()
            : [];
    
    public void Add(TKey key, TRecord record)
    {
        if (!Records.TryGetValue(key, out var records))
        {
            records = [];
            Records[key] = records;
        }

        records.Add(record);
    }
    
    public void AddRange(TKey key, IEnumerable<TRecord> records)
    {
        foreach (var record in records) Add(key, record);
    }
    
    public void Clear()
    {
        Records.Clear();
    }
}