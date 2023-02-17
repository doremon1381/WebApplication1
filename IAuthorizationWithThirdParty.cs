namespace WebApplication1
{
    public interface IAuthorizationWithThirdParty
    {
        public string ClientId { get; set; }
        public string ProjectId { get; set; }
        public string AuthUri { get; set; }
        public string TokenUri { get; set; }
        public string ClientSecret { get; set; }
        /// <summary>
        /// TODO: I assume one uri will be used.
        /// </summary>
        public string RedirectUri { get; set; }
        public string Scopes { get; set; }
    }
}
