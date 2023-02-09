namespace WebApplication1
{
    public interface IOauth2Server
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

    public class GoogleAuthorizationSetting : IOauth2Server
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
    /// TODO: will add later
    /// </summary>
    public class FacebookAuthorizationInfo : IOauth2Server
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
        public GoogleAuthorizationSetting Google { get; set; }

        // TODO: facebook
    }

    /// <summary>
    /// TODO: will add facebook
    /// </summary>
    public class AuthorizationThirdPartySetting : IAuthorizationThirdPartySetting
    {
        public GoogleAuthorizationSetting Google { get; set; }

        private static string AUTHORIZATION_THIRD_PARTY_SETTING = string.Format(nameof(AuthorizationThirdPartySetting));
        private static string GOOGLE = "Google";
        private static string CLIENTID = "ClientId";
        private static string CLIENTSECRET = "ClientSecret";

        public static string GetGoogleClientIdJsonConfigure()
        {
            return $"{AUTHORIZATION_THIRD_PARTY_SETTING}:{GOOGLE}:{CLIENTID}";
        }

        public static string GetGoogleClientSecretJsonConfigure()
        {
            return $"{AUTHORIZATION_THIRD_PARTY_SETTING}:{GOOGLE}:{CLIENTSECRET}";
        }
        // TODO: facebook
    }
}
