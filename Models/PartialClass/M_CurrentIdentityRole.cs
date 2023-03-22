using System.Security.Claims;

namespace WebApplication1.Models
{
    public partial class M_CurrentIdentityRole
    {
        //
        // Summary:
        //     Reads the type and value from the Claim.
        //
        // Parameters:
        //   claim:
        public virtual void InitializeFromClaim(Claim claim)
        {

        }

        //
        // Summary:
        //     Converts the entity into a Claim instance.
        public virtual Claim ToClaim()
        {
            // TODO: temporary
            return null;
        }
    }
}
