using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Authentication;

namespace Faactory.Extensions.Authentication
{
    public class HmacAuthenticationSchemeOptions : AuthenticationSchemeOptions
    {
        [Required]
        public byte[] Secret { get; set; }
    }
}
