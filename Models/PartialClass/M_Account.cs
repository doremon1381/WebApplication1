using System;

namespace WebApplication1.Models
{
    /// <summary>
    /// Set value for identityUser's properies
    /// </summary>
    public partial class Account
    {
        public override string NormalizedUserName { get; set; } = string.Empty;
        public override string NormalizedEmail { get; set; } = string.Empty;
        public override string PasswordHash { get; set; } = string.Empty;
        public override string PhoneNumber { get; set; } = string.Empty;
        /// <summary>
        /// default is DateTimeOffset.MinValue
        /// </summary>
        public override DateTimeOffset? LockoutEnd { get; set; } = DateTimeOffset.MinValue;
    }
}
