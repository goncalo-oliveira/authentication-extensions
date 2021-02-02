using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Authentication;

namespace Faactory.Extensions.Authentication
{
    public class SecretAuthenticationSchemeOptions : AuthenticationSchemeOptions
    {
        [Required]
        public string Secret { get; set; }

        public string SecretKeyHeader { get; set; }        
    }
}
