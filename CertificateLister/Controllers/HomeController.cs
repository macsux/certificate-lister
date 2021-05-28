using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;

namespace CertificateLister.Controllers
{
    public class HomeController : Controller
    {
        private readonly ILogger<HomeController> _logger;

        public HomeController(ILogger<HomeController> logger)
        {
            _logger = logger;
        }

        [Route("/remote/{host}/{port=443}")]
        public CertInfo Remote(string host, int port)
        {
            X509Certificate2 cert = null;
            using var client = new TcpClient();
    
            //ServicePointManager.SecurityProtocol = SecurityProtocolType.Ssl3;           
            client.Connect(host, port);

            using var ssl = new SslStream(client.GetStream(), false, ValidateServerCertificate, null);
            ssl.AuthenticateAsClient(host);
            // try
            // {
            //     ssl.AuthenticateAsClient(host);
            // }
            // catch (Exception e)
            // {
            //     _logger.LogInformation(cer);
            //     return cert;
            // }
            cert = new X509Certificate2(ssl.RemoteCertificate);
            return ToCertInfo(cert);
        }
        private bool ValidateServerCertificate(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors)
        {
            return true;
        }
        public Dictionary<string, Dictionary<string, CertInfo[]>> Index()
        {
            var locations = Enum.GetValues<StoreLocation>();
            var names = Enum.GetValues<StoreName>();
            var isUnixOs = Environment.OSVersion.Platform == PlatformID.Unix || Environment.OSVersion.Platform == PlatformID.MacOSX;
            
            var combos = from location in locations.DefaultIfEmpty()
                from name in names.DefaultIfEmpty()
                select new {location, name};

            bool ValidUnitStores(StoreName name, StoreLocation location)
            {
                if (isUnixOs && location is StoreLocation.LocalMachine)
                {
                    if (name is StoreName.Root or StoreName.CertificateAuthority)
                    {
                        return true;
                    }

                    return false;
                }

                return true;
            }

            return locations
                .Select(location =>
                    {
                        return (location, stores: names.Where(x => ValidUnitStores(x, location)).Select(storeName =>
                        {
                            using var store = new X509Store(storeName, location, OpenFlags.ReadOnly);
                            var certs = store.Certificates
                                .Cast<X509Certificate2>()
                                .Select(ToCertInfo)
                                .ToArray();
                            return (storeName, certs);
                            // return new CertStore(storeName.ToString(), certs);
                        }).ToDictionary(x => x.storeName.ToString(), x => x.certs));
                    })
                .ToDictionary(x => x.location.ToString(), x => x.stores);
            
            
        }

        static CertInfo ToCertInfo(X509Certificate2 cert)
        {
            var chain = new X509Chain();
            chain.Build(cert);

            CertInfo certInfo = null;
            for (int i = chain.ChainElements.Count - 1; i >= 0; i--)
            {
                var certElement = chain.ChainElements[i];
                certInfo = new CertInfo(
                    certElement.Certificate.FriendlyName,
                    certElement.Certificate.Subject,
                    certElement.Certificate.Thumbprint,
                    certElement.Certificate.NotBefore,
                    certElement.Certificate.NotAfter,
                    certInfo,
                    certElement.Certificate.Verify(),
                    certElement.ChainElementStatus.Select(x => x.StatusInformation.ToString()).ToArray());
            }

            chain.Reset();
            return certInfo;
        }
        
    }

    
    public record CertInfo(string Name, string Subject, string Thumbprint, DateTime validFrom, DateTime validTo, CertInfo Issuer, bool IsValid, string[] ValidationMessages);
}