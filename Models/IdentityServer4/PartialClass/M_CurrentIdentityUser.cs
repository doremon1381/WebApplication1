using System;

namespace WebApplication1.Models.IdentityServer4
{
    /// <summary>
    /// Set value for identityUser's properies
    /// </summary>
    public partial class CurrentIdentityUser: IDisposable
    {
        public override string NormalizedUserName { get; set; } = string.Empty;
        public override string NormalizedEmail { get; set; } = string.Empty;
        public override string PasswordHash { get; set; } = string.Empty;
        public override string PhoneNumber { get; set; } = string.Empty;
        /// <summary>
        /// default is DateTimeOffset.MinValue
        /// </summary>
        public override DateTimeOffset? LockoutEnd { get; set; } = DateTimeOffset.MinValue;

        #region https://learn.microsoft.com/en-us/dotnet/standard/garbage-collection/implementing-dispose
        // To detect redundant calls
        private bool _disposedValue;

        ~CurrentIdentityUser() => Dispose(false);

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
        #endregion
    }
}
