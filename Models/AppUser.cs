// ASP.NET Identity kullanıcı modeli - ek özelliklerle genişletilmiş

using Microsoft.AspNetCore.Identity;

namespace FileManagementPortal.Models
{
    public class AppUser : IdentityUser
    {
        // Kullanıcı kayıt tarihi
        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

        // Admin panelinde şifre gösterimi için
        public string? PlainPassword { get; set; }
    }
}
