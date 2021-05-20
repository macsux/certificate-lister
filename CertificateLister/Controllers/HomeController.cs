using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.Mvc;

namespace CertificateLister.Controllers
{
    public class HomeController : Controller
    {
       

        public IEnumerable<CertStore> Index()
        {
            var locations = Enum.GetValues<StoreLocation>();
            var names = Enum.GetValues<StoreName>();
            var combos = from location in locations.DefaultIfEmpty()
                from name in names.DefaultIfEmpty()
                select new {location, name};

            
            return combos.Select(combo =>
            {
                using var store = new X509Store(combo.name, combo.location, OpenFlags.ReadOnly);
                var certs = store.Certificates
                    .Cast<X509Certificate2>()
                    .Select(cert =>
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
                                certInfo,
                                certElement.Certificate.Verify(),
                                certElement.ChainElementStatus.Select(x => x.StatusInformation.ToString()).ToArray());
                        }
                   
                        chain.Reset();
                        return certInfo;
                    })
                    .ToArray();
                
                return new CertStore(combo.name.ToString(), combo.location.ToString(), certs);
            });
            
            
        }

        
    }

    public record CertStore(string StoreName, string StoreLocation, CertInfo[] Certificates);
    public record CertInfo(string Name, string Subject, string Thumbprint, CertInfo Issuer, bool IsValid, string[] ValidationMessages);
}