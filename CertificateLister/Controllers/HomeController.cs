using System;
using System.Collections.Generic;
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
                    .Select(x => new CertInfo(x.FriendlyName, x.Thumbprint, x.Issuer, combo.name.ToString(), combo.ToString()))
                    .ToArray();
                return new CertStore(combo.name.ToString(), combo.location.ToString(), certs);
            });
            
            
        }

        
    }

    public record CertStore(string Name, string Location, CertInfo[] Certificates);
    public record CertInfo(string Name, string Thumbprint, string Issuer, string StoreName, string StoreLocation);
}