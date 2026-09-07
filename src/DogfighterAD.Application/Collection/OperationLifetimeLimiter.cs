namespace DogfighterAD.Application.Collection;

internal sealed class OperationLifetimeLimiter
{
    private readonly int _capacity;
    private int _outstanding;

    public OperationLifetimeLimiter(int capacity)
    {
        if (capacity < 1)
        {
            throw new ArgumentOutOfRangeException(nameof(capacity));
        }

        _capacity = capacity;
    }

    public int Capacity => _capacity;
    public int OutstandingCount => Volatile.Read(ref _outstanding);

    public bool TryAcquire(out IDisposable? lease)
    {
        while (true)
        {
            var current = Volatile.Read(ref _outstanding);
            if (current >= _capacity)
            {
                lease = null;
                return false;
            }

            if (Interlocked.CompareExchange(ref _outstanding, current + 1, current) == current)
            {
                lease = new Lease(this);
                return true;
            }
        }
    }

    private void Release()
    {
        var remaining = Interlocked.Decrement(ref _outstanding);
        if (remaining < 0)
        {
            Interlocked.Exchange(ref _outstanding, 0);
            throw new InvalidOperationException("Operation lifetime limiter was released more than once.");
        }
    }

    private sealed class Lease : IDisposable
    {
        private OperationLifetimeLimiter? _owner;

        public Lease(OperationLifetimeLimiter owner)
        {
            _owner = owner;
        }

        public void Dispose()
        {
            Interlocked.Exchange(ref _owner, null)?.Release();
        }
    }
}
