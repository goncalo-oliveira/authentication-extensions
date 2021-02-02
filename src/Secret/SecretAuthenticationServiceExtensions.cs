using System;
using Microsoft.AspNetCore.Authentication;
using Faactory.Extensions.Authentication;

namespace Microsoft.Extensions.DependencyInjection
{
    public static class SecretAuthenticationServiceExtensions
    {
        public static IServiceCollection AddSecretAuthentication( this IServiceCollection services, Action<SecretAuthenticationSchemeOptions> configure )
        {
            services.AddSingleton<ISystemClock, SystemClock>();
            services.AddWebEncoders();
            services.AddAuthenticationCore( options =>
            {
                options.AddScheme<SecretAuthenticationHandler>( "secret-key", "Secret Authentication" );

                options.DefaultScheme = "secret-key";
            } );

            services.Configure<SecretAuthenticationSchemeOptions>( schemeOptions => configure( schemeOptions ) );

            return ( services );
        }
    }
}
