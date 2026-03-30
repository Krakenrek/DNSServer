namespace DNS.Storage;

public interface IDomainRecordHolder<in TKey, TRecord> where TKey : notnull
{
    IReadOnlyList<TRecord> this[TKey key] { get; }

    void Add(TKey key, TRecord record);
}

public class SimpleRecordHolder<TKey, TRecord> : IDomainRecordHolder<TKey, TRecord> where TKey : notnull
{
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