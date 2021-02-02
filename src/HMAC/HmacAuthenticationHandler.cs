using System;
using System.IO;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Encodings.Web;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.Net.Http.Headers;

namespace Faactory.Extensions.Authentication
{
    public class HmacAuthenticationHandler : AuthenticationHandler<HmacAuthenticationSchemeOptions>
    {
        private readonly byte[] secretValue;

        public HmacAuthenticationHandler( IOptionsMonitor<HmacAuthenticationSchemeOptions> optionsAccessor
                , ILoggerFactory loggerFactory
                , UrlEncoder urlEncoder
                , ISystemClock systemClock )
            : base( optionsAccessor, loggerFactory, urlEncoder, systemClock )
        {
            var options = optionsAccessor.CurrentValue;

            secretValue = options.Secret;
        }

        protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            var auth = Context.Request.Headers[HeaderNames.Authorization];

            if ( string.IsNullOrEmpty( auth ) )
            {
                return AuthenticateResult.NoResult();
            }

            var parts = auth.ToString().Trim().Split( (char)0x20 );

            if ( ( parts.Length != 2 ) || !parts[0].Equals( "hmac", StringComparison.OrdinalIgnoreCase ) )
            {
                // wrong length or
                // wrong scheme

                return AuthenticateResult.NoResult();
            }

            // hmac values should be composed by
            // random_key:hmac_hash
            var hmacValues = parts[1].Split( (char)0x3A );

            if ( hmacValues.Length != 2 )
            {
                // wrong length
                return AuthenticateResult.Fail( new UnauthorizedAccessException() );
            }

            // generate md5 for content (if any) to guarantee message integrity
            var contentBase64 = string.Empty;

            using ( var ms = new MemoryStream() )
            {
                await Context.Request.Body.CopyToAsync( ms );

                if ( ms.Length > 0 )
                {
                    using ( var md5 = MD5.Create() )
                    {
                        var hash = await md5.ComputeHashAsync( ms );

                        contentBase64 = Convert.ToBase64String( hash );
                    }
                }
            }

            // the hmac_hash is generated from the following values
            // random_key HTTP_METHOD url [content_hash]
            var value = string.Join( (char)0x20, new string[]
            {
                hmacValues[0],
                Context.Request.Method,
                Context.Request.Path,
                contentBase64
            }.Where( x => !string.IsNullOrEmpty( x ) )  );

            var valueBytes = Encoding.UTF8.GetBytes( value );

            // compute hmac_hash
            var hmacValue = string.Empty;
            using ( HMACSHA256 hmac = new HMACSHA256( secretValue ) )
            {
                var hash = hmac.ComputeHash( valueBytes );
                hmacValue = Convert.ToBase64String( hash );
            }

            if ( hmacValue != hmacValues[1] )
            {
                return AuthenticateResult.Fail( new UnauthorizedAccessException() );
            }

            var identity = new ClaimsIdentity( "hmac" );
            var ticket = new AuthenticationTicket( new ClaimsPrincipal( identity ), "hmac" );

            return AuthenticateResult.Success( ticket );
        }
    }
}
