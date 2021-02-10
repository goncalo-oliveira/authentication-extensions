using System;
using System.IO;
using System.Security.Claims;
using System.Text;
using System.Text.Encodings.Web;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Primitives;
using Microsoft.Net.Http.Headers;

namespace Faactory.Extensions.Authentication
{
    public class SecretAuthenticationHandler : AuthenticationHandler<SecretAuthenticationSchemeOptions>
    {
        private readonly string secretValue;
        private readonly string secretKeyHeader;

        public SecretAuthenticationHandler( IOptionsMonitor<SecretAuthenticationSchemeOptions> optionsAccessor
                , ILoggerFactory loggerFactory
                , UrlEncoder urlEncoder
                , ISystemClock systemClock )
            : base( optionsAccessor, loggerFactory, urlEncoder, systemClock )
        {
            var options = optionsAccessor.CurrentValue;

            secretKeyHeader = options.SecretKeyHeader;
            secretValue = options.Secret;
        }

        protected override Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            // if we don't have a header key configured
            // we look into Authorization: Secret value
            // if we do have a header key, we retrieve the value directly

            var value = !string.IsNullOrEmpty( secretKeyHeader )
                ? Context.Request.Headers[secretKeyHeader]
                : StringValues.Empty;

            if ( string.IsNullOrEmpty( value ) )
            {
                // attempt to retrieve from Authorization header
                value = Context.Request.Headers[HeaderNames.Authorization];

                if ( string.IsNullOrEmpty( value ) )
                {
                    return Task.FromResult( AuthenticateResult.NoResult() );
                }

                // authorization scheme must be 'Secret'
                var parts = value.ToString().Trim().Split( (char)0x20 );

                if ( ( parts.Length != 2 ) || !parts[0].Equals( "secret", StringComparison.OrdinalIgnoreCase ) )
                {
                    // wrong scheme
                    return Task.FromResult( AuthenticateResult.NoResult() );
                }

                value = parts[1];
            }

            if ( value != secretValue )
            {
                return Task.FromResult( AuthenticateResult.Fail( new UnauthorizedAccessException() ) );
            }

            var identity = new ClaimsIdentity( "Secret Key" );

            var ticket = new AuthenticationTicket( new ClaimsPrincipal( identity ), "secret-key" );

            return Task.FromResult( AuthenticateResult.Success( ticket ) );
        }
    }
}
