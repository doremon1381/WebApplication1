namespace WebApplication1
{
    /// <summary>
    /// IDEA: using for authrorization with Google
    /// </summary>
    public class GoogleClientSetting : IAuthorizationWithThirdParty
    {
        public string ClientId { get; set; }
        public string ProjectId { get; set; }
        public string AuthUri { get; set; }
        public string TokenUri { get; set; }
        public string ClientSecret { get; set; }
        public string RedirectUri { get; set; }
        public string Scopes { get; set; }
    }

    /// <summary>
    /// TODO: using for authorization with Facebook
    /// </summary>
    public class FacebookClientSetting : IAuthorizationWithThirdParty
    {
        public string ClientId { get; set; }
        public string ProjectId { get; set; }
        public string AuthUri { get; set; }
        public string TokenUri { get; set; }
        public string ClientSecret { get; set; }
        public string RedirectUri { get; set; }
        public string Scopes { get; set; }
    }

    /// <summary>
    /// TODO: will add facebook
    /// </summary>
    public interface IAuthorizationThirdPartySetting
    {
        public GoogleClientSetting Google { get; set; }

        // TODO: facebook
    }

    /// <summary>
    /// TODO: will add facebook
    /// </summary>
    public class AuthorizationThirdPartySetting : IAuthorizationThirdPartySetting
    {
        public GoogleClientSetting Google { get; set; }

        // TODO: facebook
    }
}
