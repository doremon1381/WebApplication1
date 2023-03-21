using Microsoft.Extensions.Configuration;
using System;

namespace WebApplication1
{
    public static class AppSettingExtensions
    {
        //private static string GOOGLE = "Google";
        // default implement of OAuth2
        private static string CLIENTID = "ClientId";
        private static string CLIENTSECRET = "ClientSecret";

        // IDEA: for OpenIDConnection
        private static string AUTHORITY = "Authority";
        // TODO: will do sth
        //private static string RESPONSETYPE = "ResponseType";

        private static string AUTHORIZATION_THIRD_PARTY_SETTING = string.Format(nameof(AuthorizationThirdPartySetting));
        private static string OPENID_CONNECTION_CLIENT_SETTING = string.Format(nameof(OpenIDConnectionClient));
        private static string DATABASE_CONFIG_REGION = string.Format(nameof(FinalProjectDatabaseSetting));
        //private static string DATABASE_NAME = string.Empty;
        //private static string CONNECTION_STRING = string.Empty;
        //private static string UseToGetConnectionStringFromAppSettings => $"{DATABASE_CONFIG_REGION}:ConnectionString";
        //private static string UseToGetDatabaseNameFromAppSettings => $"{DATABASE_CONFIG_REGION}:DatabaseName";

        internal static string DatabaseName { get; private set; }
        internal static string ConnectionString { get; private set; }
        internal static string Authority { get; private set; }
        internal static string ClientId { get; private set; }
        internal static string ClientSecret { get; private set; }

        /// <summary>
        /// TODO: default password
        /// </summary>
        internal static string SignInCredentialCryptoServicesPassword { get; private set; } = "nokia1200";

        private static void SetDatabaseName(string dbName)
        {
            if (string.IsNullOrEmpty(DatabaseName))
                DatabaseName = dbName;
        }

        private static void SetConnectionString(string cn)
        {
            if (string.IsNullOrEmpty(ConnectionString))
                ConnectionString = cn;
        }

        internal static void GetFromAppSettings(IConfiguration config)
        {
            SetDatabaseName(config.GetValue<string>($"{DATABASE_CONFIG_REGION}:DatabaseName"));
            SetConnectionString(config.GetValue<string>($"{DATABASE_CONFIG_REGION}:ConnectionString"));

            Authority = config.GetValue<string>($"{OPENID_CONNECTION_CLIENT_SETTING}:{AUTHORITY}");
            ClientId = config.GetValue<string>($"{OPENID_CONNECTION_CLIENT_SETTING}:{CLIENTID}");
            ClientSecret = config.GetValue<string>($"{OPENID_CONNECTION_CLIENT_SETTING}:{CLIENTSECRET}");
        }

    }

    /// <summary>
    /// IDEAL: using for getting value in appSetting.json.
    /// </summary>
    public enum OAuthConfig
    {
        CLIENTID,
        CLIENTSECRET,
    }

    // TODO: willl check again
    public enum OpenIDConnectionConfig
    {
        AUTHORITY,
        CLIENTID,
        CLIENTSECRET
        // TODO: will do sth
        //RESPONSETYPE
    }
}
