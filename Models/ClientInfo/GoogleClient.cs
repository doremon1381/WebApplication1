using Google.Apis.Auth;

namespace WebApplication1.Models.ClientInfo
{
    // TODO: coppy from GoogleJsonWebSignature.Payload
    // Summary:
    //     The payload as specified in https://developers.google.com/accounts/docs/OAuth2ServiceAccount#formingclaimset,
    //     https://developers.google.com/identity/protocols/OpenIDConnect, and https://openid.net/specs/openid-connect-core-1_0.html#StandardClaims
    public class GoogleClient 
    {
        //
        // Summary:
        //     A space-delimited list of the permissions the application requests or null.
        public string Scope
        {
            get;
            set;
        }

        //
        // Summary:
        //     The email address of the user for which the application is requesting delegated
        //     access.
        public string Prn
        {
            get;
            set;
        }

        //
        // Summary:
        //     The hosted GSuite domain of the user. Provided only if the user belongs to a
        //     hosted domain.
        public string HostedDomain
        {
            get;
            set;
        }

        //
        // Summary:
        //     The user's email address. This may not be unique and is not suitable for use
        //     as a primary key. Provided only if your scope included the string "email".
        public string Email
        {
            get;
            set;
        }

        //
        // Summary:
        //     True if the user's e-mail address has been verified; otherwise false.
        public bool EmailVerified
        {
            get;
            set;
        }

        //
        // Summary:
        //     The user's full name, in a displayable form. Might be provided when: (1) The
        //     request scope included the string "profile"; or (2) The ID token is returned
        //     from a token refresh. When name claims are present, you can use them to update
        //     your app's user records. Note that this claim is never guaranteed to be present.
        public string Name
        {
            get;
            set;
        }

        //
        // Summary:
        //     Given name(s) or first name(s) of the End-User. Note that in some cultures, people
        //     can have multiple given names; all can be present, with the names being separated
        //     by space characters.
        public string GivenName
        {
            get;
            set;
        }

        //
        // Summary:
        //     Surname(s) or last name(s) of the End-User. Note that in some cultures, people
        //     can have multiple family names or no family name; all can be present, with the
        //     names being separated by space characters.
        public string FamilyName
        {
            get;
            set;
        }

        //
        // Summary:
        //     The URL of the user's profile picture. Might be provided when: (1) The request
        //     scope included the string "profile"; or (2) The ID token is returned from a token
        //     refresh. When picture claims are present, you can use them to update your app's
        //     user records. Note that this claim is never guaranteed to be present.
        public string Picture
        {
            get;
            set;
        }

        //
        // Summary:
        //     End-User's locale, represented as a BCP47 [RFC5646] language tag. This is typically
        //     an ISO 639-1 Alpha-2 [ISO639‑1] language code in lowercase and an ISO 3166-1
        //     Alpha-2 [ISO3166‑1] country code in uppercase, separated by a dash. For example,
        //     en-US or fr-CA.
        public string Locale
        {
            get;
            set;
        }

        public static GoogleClient MappingWithGooglePayload(GoogleJsonWebSignature.Payload payload)
        {
            var newObj = new GoogleClient()
            {
                Scope = payload.Scope,
                Prn = payload.Prn,
                HostedDomain = payload.HostedDomain,
                Email = payload.Email,
                Name = payload.Name,
                GivenName = payload.GivenName,
                FamilyName = payload.FamilyName,
                Picture = payload.Picture,
                Locale = payload.Locale,
                EmailVerified = payload.EmailVerified,
            };

            return newObj;
        }
    }
}
