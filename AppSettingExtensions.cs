namespace WebApplication1
{
    public static class AppSettingExtensions
    {
        private static string GOOGLE = "Google";
        // default implement of OAuth2
        private static string CLIENTID = "ClientId";
        private static string CLIENTSECRET = "ClientSecret";

        // IDEA: for OpenIDConnection
        private static string AUTHORITY = "Authority";
        // TODO: will do sth
        //private static string RESPONSETYPE = "ResponseType";

        private static string AUTHORIZATION_THIRD_PARTY_SETTING = string.Format(nameof(AuthorizationThirdPartySetting));
        private static string OPENID_CONNECTION_CLIENT_SETTING = string.Format(nameof(OpenIDConnectionClient));
        private static string DATABASE_NAME = string.Format(nameof(FinalProjectDatabaseSetting));
        
        public static string GoogleConfigAddress(OAuthConfig name)
        {
            if (OAuthConfig.CLIENTID.Equals(name))
            {
                return $"{AUTHORIZATION_THIRD_PARTY_SETTING}:{GOOGLE}:{CLIENTID}";
            }
            else if (OAuthConfig.CLIENTSECRET.Equals(name))
            {
                return $"{AUTHORIZATION_THIRD_PARTY_SETTING}:{GOOGLE}:{CLIENTSECRET}";
            }
            else
                return "";

        }

        public static string OpenIDConnectConfigAddress(OpenIDConnectionConfig name)
        {
            if (OpenIDConnectionConfig.AUTHORITY.Equals(name))
            {
                return $"{OPENID_CONNECTION_CLIENT_SETTING}:{AUTHORITY}";
            }
            else if (OpenIDConnectionConfig.CLIENTID.Equals(name))
            {
                return $"{OPENID_CONNECTION_CLIENT_SETTING}:{CLIENTID}";
            }
            else if (OpenIDConnectionConfig.CLIENTSECRET.Equals(name))
            {
                return $"{OPENID_CONNECTION_CLIENT_SETTING}:{CLIENTSECRET}";
            }
            // TODO: will do sth
            //else if(OpenIDConnectionConfig.RESPONSETYPE.Equals(name))
            //{
            //    return $"{OPENID_CONNECTION_CLIENT_SETTING}:{RESPONSETYPE}";
            //}
            else
                return "";
        }

        public static string DatabaseConnectionAddress => $"{DATABASE_NAME}:ConnectionString";
    }

    /// <summary>
    /// IDEAL: using for getting value in appSetting.json.
    /// </summary>
    public enum OAuthConfig
    {
        CLIENTID,
        CLIENTSECRET,
    }

    public enum OpenIDConnectionConfig
    {
        AUTHORITY,
        CLIENTID,
        CLIENTSECRET
        // TODO: will do sth
        //RESPONSETYPE
    }
}
