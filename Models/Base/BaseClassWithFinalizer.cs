using System;

namespace WebApplication1.Models.Base
{
    /// <summary>
    /// TODO: need to learn more
    /// https://learn.microsoft.com/en-us/dotnet/standard/garbage-collection/implementing-dispose
    /// </summary>
    public class DerivedClassWithFinalizer : BaseClassWithFinalizer
    {
        // To detect redundant calls
        private bool _disposedValue;

        ~DerivedClassWithFinalizer() => this.Dispose(false);

        // Protected implementation of Dispose pattern.
        protected override void Dispose(bool disposing)
        {
            if (!_disposedValue)
            {
                if (disposing)
                {
                    // TODO: dispose managed state (managed objects).
                }

                // TODO: free unmanaged resources (unmanaged objects) and override a finalizer below.
                // TODO: set large fields to null.
                _disposedValue = true;
            }

            // Call the base class implementation.
            base.Dispose(disposing);
        }
    }

    /// <summary>
    /// TODO: need to learn more
    /// https://learn.microsoft.com/en-us/dotnet/standard/garbage-collection/implementing-dispose
    /// </summary>
    public class BaseClassWithFinalizer : IDisposable
    {
        // To detect redundant calls
        private bool _disposedValue;

        ~BaseClassWithFinalizer() => Dispose(false);

        // Public implementation of Dispose pattern callable by consumers.
        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        // Protected implementation of Dispose pattern.
        protected virtual void Dispose(bool disposing)
        {
            if (!_disposedValue)
            {
                if (disposing)
                {
                    // TODO: dispose managed state (managed objects)
                }

                // TODO: free unmanaged resources (unmanaged objects) and override finalizer
                // TODO: set large fields to null
                _disposedValue = true;
            }
        }
    }
}
