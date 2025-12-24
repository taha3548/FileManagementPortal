// Kullanıcı servisi arayüzü - Identity işlemleri için

using FileManagementPortal.Models;

namespace FileManagementPortal.Services
{
    public interface ICustomUserService
    {
        // Kullanıcı bulma işlemleri
        Task<AppUser?> FindByEmailAsync(string email);
        Task<AppUser?> FindByIdAsync(string id);
        Task<IEnumerable<AppUser>> GetAllAsync();
        
        // Rol işlemleri
        Task<IList<string>> GetRolesAsync(AppUser user);
        Task<bool> IsInRoleAsync(AppUser user, string roleName);
        Task<bool> EnsureRoleExistsAsync(string roleName);
        Task<bool> AddToRoleAsync(AppUser user, string roleName);
        Task<bool> RemoveFromRoleAsync(AppUser user, string roleName);

        // Kullanıcı CRUD işlemleri
        Task<(bool Success, string? ErrorMessage)> CreateAsync(string email, string password, IEnumerable<string>? roles = null);
        Task<bool> UpdatePasswordAsync(AppUser user, string newPassword);
        Task<bool> DeleteAsync(AppUser user);
        Task<bool> UpdateAsync(AppUser user);
        
        // Kimlik doğrulama
        Task<(bool Success, AppUser? User, string? ErrorMessage)> ValidateUserAsync(string email, string password);
    }
}
