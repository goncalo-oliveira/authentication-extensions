using System;
using Microsoft.AspNetCore.Authentication;
using Faactory.Extensions.Authentication;

namespace Microsoft.Extensions.DependencyInjection
{
    public static class HmacAuthenticationServiceExtensions
    {
        public static IServiceCollection AddHmacAuthentication( this IServiceCollection services, Action<HmacAuthenticationSchemeOptions> configure )
        {
            services.AddSingleton<ISystemClock, SystemClock>();
            services.AddWebEncoders();
            services.AddAuthenticationCore( options =>
            {
                options.AddScheme<HmacAuthenticationHandler>( "hmac", "HMAC Authentication" );

                options.DefaultScheme = "hmac";
            } );

            services.Configure<HmacAuthenticationSchemeOptions>( schemeOptions => configure( schemeOptions ) );

            return ( services );
        }
    }
}
