using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Autofac;
using Autofac.Integration.WebApi;
using IdentityServer3.Core.Endpoints;
using IdentityServer3.Core.Models;
using IdentityServer3.Core.ResponseHandling;
using IdentityServer3.Core.Services;
using IdentityServer3.Core.Services.Default;
using IdentityServer3.Core.Services.InMemory;
using IdentityServer3.Core.Validation;
using Microsoft.Owin;

namespace IdentityServer3.Core.Configuration.Hosting
{
    public class AutofacModule : Module
    {
        private readonly IdentityServerOptions options;

        public AutofacModule(IdentityServerOptions options)
        {
            this.options = options;
        }

        protected override void Load(ContainerBuilder builder)
        {
            IdentityServerServiceFactory fact = options.Factory;
            fact.Validate();


            builder.RegisterInstance(options).AsSelf();

            // mandatory from factory
            builder.Register(fact.ScopeStore);
            builder.Register(fact.ClientStore);
            builder.RegisterDecorator<IUserService, ExternalClaimsFilterUserService>(fact.UserService);

            // optional from factory
            builder.RegisterDecoratorDefaultInstance<IAuthorizationCodeStore, KeyHashingAuthorizationCodeStore, InMemoryAuthorizationCodeStore>(fact.AuthorizationCodeStore);
            builder.RegisterDecoratorDefaultInstance<ITokenHandleStore, KeyHashingTokenHandleStore, InMemoryTokenHandleStore>(fact.TokenHandleStore);
            builder.RegisterDecoratorDefaultInstance<IRefreshTokenStore, KeyHashingRefreshTokenStore, InMemoryRefreshTokenStore>(fact.RefreshTokenStore);

            builder.RegisterDefaultInstance<IConsentStore, InMemoryConsentStore>(fact.ConsentStore);
            builder.RegisterDefaultInstance<ICorsPolicyService, DefaultCorsPolicyService>(fact.CorsPolicyService);

            builder.RegisterDefaultType<IClaimsProvider, DefaultClaimsProvider>(fact.ClaimsProvider);
            builder.RegisterDefaultType<ITokenService, DefaultTokenService>(fact.TokenService);
            builder.RegisterDefaultType<IRefreshTokenService, DefaultRefreshTokenService>(fact.RefreshTokenService);
            builder.RegisterDefaultType<ICustomRequestValidator, DefaultCustomRequestValidator>(fact.CustomRequestValidator);
            builder.RegisterDefaultType<IExternalClaimsFilter, NopClaimsFilter>(fact.ExternalClaimsFilter);
            builder.RegisterDefaultType<ICustomTokenValidator, DefaultCustomTokenValidator>(fact.CustomTokenValidator);
            builder.RegisterDefaultType<ICustomTokenResponseGenerator, DefaultCustomTokenResponseGenerator>(fact.CustomTokenResponseGenerator);
            builder.RegisterDefaultType<IConsentService, DefaultConsentService>(fact.ConsentService);
            builder.RegisterDefaultType<IAuthenticationSessionValidator, DefaultAuthenticationSessionValidator>(fact.AuthenticationSessionValidator);

            // todo remove in next major version
            if (fact.TokenSigningService != null)
            {
                builder.Register(fact.TokenSigningService);
            }
            else
            {
                builder.Register(new Registration<ITokenSigningService>(r => new DefaultTokenSigningService(r.Resolve<ISigningKeyService>())));
            }

            builder.RegisterDefaultType<ISigningKeyService, DefaultSigningKeyService>(fact.SigningKeyService);
            builder.RegisterDecoratorDefaultType<IEventService, EventServiceDecorator, DefaultEventService>(fact.EventService);

            builder.RegisterDefaultType<IRedirectUriValidator, DefaultRedirectUriValidator>(fact.RedirectUriValidator);
            builder.RegisterDefaultType<ILocalizationService, DefaultLocalizationService>(fact.LocalizationService);
            builder.RegisterDefaultType<IClientPermissionsService, DefaultClientPermissionsService>(fact.ClientPermissionsService);

            // register custom grant validators
            builder.RegisterType<CustomGrantValidator>();
            if (fact.CustomGrantValidators.Any())
            {
                foreach (var val in fact.CustomGrantValidators)
                {
                    builder.Register(val);
                }
            }

            // register secret parsing/validation plumbing
            builder.RegisterType<SecretValidator>();
            builder.RegisterType<SecretParser>();

            foreach (var parser in fact.SecretParsers)
            {
                builder.Register(parser);
            }
            foreach (var validator in fact.SecretValidators)
            {
                builder.Register(validator);
            }

            // register view service plumbing
            if (fact.ViewService == null)
            {
                fact.ViewService = new DefaultViewServiceRegistration();
            }
            builder.Register(fact.ViewService);

            // this is more of an internal interface, but maybe we want to open it up as pluggable?
            // this is used by the DefaultClientPermissionsService below, or it could be used
            // by a custom IClientPermissionsService
            builder.Register(ctx =>
            {
                var consent = ctx.Resolve<IConsentStore>();
                var refresh = ctx.Resolve<IRefreshTokenStore>();
                var code = ctx.Resolve<IAuthorizationCodeStore>();
                var access = ctx.Resolve<ITokenHandleStore>();
                return new AggregatePermissionsStore(
                    consent,
                    new TokenMetadataPermissionsStoreAdapter(refresh.GetAllAsync, refresh.RevokeAsync),
                    new TokenMetadataPermissionsStoreAdapter(code.GetAllAsync, code.RevokeAsync),
                    new TokenMetadataPermissionsStoreAdapter(access.GetAllAsync, access.RevokeAsync)
                );
            }).As<IPermissionsStore>();

            // validators
            builder.RegisterType<TokenRequestValidator>();
            builder.RegisterType<AuthorizeRequestValidator>();
            builder.RegisterType<TokenValidator>();
            builder.RegisterType<EndSessionRequestValidator>();
            builder.RegisterType<BearerTokenUsageValidator>();
            builder.RegisterType<ScopeValidator>();
            builder.RegisterType<TokenRevocationRequestValidator>();
            builder.RegisterType<IntrospectionRequestValidator>();
            builder.RegisterType<ScopeSecretValidator>();
            builder.RegisterType<ClientSecretValidator>();

            // processors
            builder.RegisterType<TokenResponseGenerator>();
            builder.RegisterType<AuthorizeResponseGenerator>();
            builder.RegisterType<AuthorizeInteractionResponseGenerator>();
            builder.RegisterType<UserInfoResponseGenerator>();
            builder.RegisterType<EndSessionResponseGenerator>();
            builder.RegisterType<IntrospectionResponseGenerator>();

            // for authentication
            var authenticationOptions = options.AuthenticationOptions ?? new AuthenticationOptions();
            builder.RegisterInstance(authenticationOptions).AsSelf();

            // load core controller
            builder.RegisterApiControllers(typeof(AuthorizeEndpointController).Assembly);

            // other internal
            builder.Register(c => new OwinEnvironmentService(c.Resolve<IOwinContext>()));
            builder.Register(c => new SessionCookie(c.Resolve<IOwinContext>(), c.Resolve<IdentityServerOptions>()));
            builder.Register(c => new MessageCookie<SignInMessage>(c.Resolve<IOwinContext>(), c.Resolve<IdentityServerOptions>()));
            builder.Register(c => new MessageCookie<SignOutMessage>(c.Resolve<IOwinContext>(), c.Resolve<IdentityServerOptions>()));
            builder.Register(c => new LastUserNameCookie(c.Resolve<IOwinContext>(), c.Resolve<IdentityServerOptions>()));
            builder.Register(c => new AntiForgeryToken(c.Resolve<IOwinContext>(), c.Resolve<IdentityServerOptions>()));
            builder.Register(c => new ClientListCookie(c.Resolve<IOwinContext>(), c.Resolve<IdentityServerOptions>()));

            // add any additional dependencies from hosting application
            foreach (var registration in fact.Registrations)
            {
                builder.Register(registration, registration.Name);
            }


        }
    }
}
