﻿using System;
using System.Collections.Generic;
using System.Linq;
using Thinktecture.IdentityServer.Core.Protocols.Connect.Models;

namespace Thinktecture.IdentityServer.Core.Protocols.Connect.Repositories
{
    public class InMemoryOidcClientsRepository : IOidcClientsRepository
    {
        private static readonly List<OidcClient> _clients;

        static InMemoryOidcClientsRepository()
        {
            _clients = new List<OidcClient>
            {
                new OidcClient
                {
                    ClientName = "Code Client",
                    ClientId = "codeclient",
                    ClientSecret = "secret",
                    Flow = Flows.Code,
                    ApplicationType = ApplicationTypes.Web,
                    RequireConsent = false,
                    
                    RedirectUris = new List<Uri>
                    {
                        new Uri("https://localhost/cb")
                    },
                    
                    ScopeRestrictions = new List<string>
                    { 
                        Constants.StandardScopes.Profile 
                    },

                    SigningKeyType = SigningKeyTypes.ClientSecret,
                    SubjectType = SubjectTypes.Global,
                    
                    IdentityTokenLifetime = 360,
                    AccessTokenLifetime = 360,
                },
                new OidcClient
                {
                    ClientName = "Implicit Client",
                    ClientId = "implicitclient",
                    ClientSecret = "secret",
                    Flow = Flows.Implicit,
                    ApplicationType = ApplicationTypes.Web,
                    RequireConsent = false,
                    
                    RedirectUris = new List<Uri>
                    {
                        new Uri("https://localhost/cb")
                    },
                    
                    ScopeRestrictions = new List<string>
                    { 
                        Constants.StandardScopes.Profile 
                    },

                    SigningKeyType = SigningKeyTypes.ClientSecret,
                    SubjectType = SubjectTypes.Global,
                    
                    IdentityTokenLifetime = 360,
                    AccessTokenLifetime = 360,
                }
            };
        }

        public OidcClient FindById(string clientId)
        {
            return (from c in _clients
                    where c.ClientId == clientId
                    select c).SingleOrDefault();
        }
    }
}