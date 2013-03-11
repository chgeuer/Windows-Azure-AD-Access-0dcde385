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
    using System.IO;
    using System.Security.Cryptography.X509Certificates;

    public static class ManagementServiceHelper
    {
        public static ManagementService CreateManagementServiceClient()
        {
            return new ManagementService(
                serviceNamespace: SamplesConfiguration.ServiceNamespace, 
                managementServiceIdentityName: SamplesConfiguration.ManagementServiceIdentityName, 
                managementServiceIdentityKey: SamplesConfiguration.ManagementServiceIdentityKey, 
                acsHostUrl: SamplesConfiguration.AcsHostUrl, 
                acsManagementServicesRelativeUrl: SamplesConfiguration.AcsManagementServicesRelativeUrl);
        }

        /// <summary>
        /// Helper function to read the content of a .pfx file to a byte array. 
        /// </summary>
        public static byte[] ReadBytesFromPfxFile(string pfxFileName, string protectionPassword)
        {
            //
            // Read the bytes from the .pfx file.
            //
            byte[] signingCertificate;
            using (FileStream stream = File.OpenRead(pfxFileName))
            {
                using (BinaryReader br = new BinaryReader(stream))
                {
                    signingCertificate = br.ReadBytes((int)stream.Length);
                }
            }

            //
            // Double check on the read byte array by creating a X509Certificate2 object which should not throw.
            //
            X509Certificate2 cert = new X509Certificate2(signingCertificate, protectionPassword);

            if (!cert.HasPrivateKey)
            {
                throw new InvalidDataException(pfxFileName + "doesn't have a private key.");
            }

            return signingCertificate;
        }
    }
}