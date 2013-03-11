//---------------------------------------------------------------------------------
// Copyright 2010 Microsoft Corporation
// Licensed under the Apache License, Version 2.0 (the "License"); 
// You may not use this file except in compliance with the License. 
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0 

// THIS CODE IS PROVIDED *AS IS* BASIS, WITHOUT WARRANTIES OR 
// CONDITIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED, 
// INCLUDING WITHOUT LIMITATION ANY IMPLIED WARRANTIES OR 
// CONDITIONS OF TITLE, FITNESS FOR A PARTICULAR PURPOSE, 
// MERCHANTABLITY OR NON-INFRINGEMENT. 

// See the Apache 2 License for the specific language governing 
// permissions and limitations under the License.
//---------------------------------------------------------------------------------

namespace Common.ACS.Management
{
    using System;
    using System.Collections.Specialized;
    using System.Data.Services.Client;
    using System.Globalization;
    using System.IO;
    using System.Net;
    using System.Runtime.Serialization;
    using System.Runtime.Serialization.Json;

    internal class ManagementServiceConstants
    {
        private ManagementServiceConstants() { }

        internal const string AcsHostUrl = "accesscontrol.windows.net";
        internal const string AcsManagementServicesRelativeUrl = "v2/mgmt/service/";
    }

    public partial class ManagementService
    {
        private string cachedSwtToken;

        internal string ServiceNamespace { get; set; }
        internal string ManagementServiceIdentityName { get; set; }
        internal string ManagementServiceIdentityKey { get; set; }
        internal string AcsHostUrl { get; set; }
        internal string AcsManagementServicesRelativeUrl { get; set; }

        public ManagementService(string serviceNamespace, string managementServiceIdentityName, string managementServiceIdentityKey)
            : this(serviceNamespace, managementServiceIdentityName, managementServiceIdentityKey, 
            ManagementServiceConstants.AcsHostUrl, ManagementServiceConstants.AcsManagementServicesRelativeUrl) { }

        public ManagementService(string serviceNamespace, string managementServiceIdentityName, string managementServiceIdentityKey, 
            string acsHostUrl, string acsManagementServicesRelativeUrl)
            : base(new Uri(String.Format(CultureInfo.InvariantCulture, "https://{0}.{1}/{2}", 
                serviceNamespace, acsHostUrl, acsManagementServicesRelativeUrl)))
        {
            this.ServiceNamespace = serviceNamespace;
            this.ManagementServiceIdentityName = managementServiceIdentityName;
            this.ManagementServiceIdentityKey = managementServiceIdentityKey;
            this.AcsHostUrl = acsHostUrl;
            this.AcsManagementServicesRelativeUrl = acsManagementServicesRelativeUrl;

            this.SendingRequest += GetTokenWithWritePermission;
        }

        /// <summary>
        /// Event handler for getting a token from ACS.
        /// </summary>
        /// <param name="sender">Sender of the event.</param>
        /// <param name="args">Event arguments.</param>
        public void GetTokenWithWritePermission(object sender, SendingRequestEventArgs args)
        {
            GetTokenWithWritePermission((HttpWebRequest) args.Request);
        }

        /// <summary>
        /// Helper function for the event handler above, adding the SWT token to the HTTP 'Authorization' header. 
        /// The SWT token is cached so that we don't need to obtain a token on every request.
        /// </summary>
        /// <param name="args">Event arguments.</param>
        public void GetTokenWithWritePermission(HttpWebRequest args)
        {
            if (cachedSwtToken == null)
            {
                cachedSwtToken = GetTokenFromACS();
            }

            args.Headers.Add(HttpRequestHeader.Authorization, "Bearer " + cachedSwtToken);
        }

        /// <summary>
        /// Obtains a SWT token from ACSv2. 
        /// </summary>
        /// <returns>A token  from ACS.</returns>
        string GetTokenFromACS()
        {
            //
            // Request a token from ACS
            //
            WebClient client = new WebClient();
            client.BaseAddress = string.Format(CultureInfo.CurrentCulture, "https://{0}.{1}", this.ServiceNamespace, this.AcsHostUrl);

            NameValueCollection values = new NameValueCollection();
            values.Add("grant_type", "client_credentials");
            values.Add("client_id", this.ManagementServiceIdentityName);
            values.Add("client_secret", this.ManagementServiceIdentityKey);
            values.Add("scope", client.BaseAddress + this.AcsManagementServicesRelativeUrl);

            byte[] responseBytes = client.UploadValues("/v2/OAuth2-13", "POST", values);

            //
            // Extract the access token and return it.
            //
            using( MemoryStream responseStream = new MemoryStream(responseBytes))
            {
                OAuth2TokenResponse tokenResponse = (OAuth2TokenResponse) new DataContractJsonSerializer(typeof(OAuth2TokenResponse)).ReadObject(responseStream);
                return tokenResponse.access_token;
            }
        }

        [DataContract]
        private class OAuth2TokenResponse
        {
            [DataMember]
            public string access_token;
        }
    }
}