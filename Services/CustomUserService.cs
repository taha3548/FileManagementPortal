// ============================================
// CUSTOM USER SERVICE - Kullanıcı Servisi
// ============================================
// ASP.NET Identity ile kullanıcı işlemleri
// UserManager, RoleManager, SignInManager
// Rol yönetimi (Admin, User)
// ============================================

using FileManagementPortal.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

namespace FileManagementPortal.Services
{
    public class CustomUserService : ICustomUserService
    {
        private readonly UserManager<AppUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly SignInManager<AppUser> _signInManager;

        public CustomUserService(
            UserManager<AppUser> userManager,
            RoleManager<IdentityRole> roleManager,
            SignInManager<AppUser> signInManager)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _signInManager = signInManager;
        }

        public async Task<AppUser?> FindByEmailAsync(string email)
        {
            return await _userManager.FindByEmailAsync(email);
        }

        public async Task<AppUser?> FindByIdAsync(string id)
        {
            return await _userManager.FindByIdAsync(id);
        }

        public async Task<IEnumerable<AppUser>> GetAllAsync()
        {
            return await _userManager.Users.ToListAsync();
        }

        public async Task<IList<string>> GetRolesAsync(AppUser user)
        {
            return await _userManager.GetRolesAsync(user);
        }

        public async Task<bool> IsInRoleAsync(AppUser user, string roleName)
        {
            return await _userManager.IsInRoleAsync(user, roleName);
        }

        // Rol yoksa oluştur
        public async Task<bool> EnsureRoleExistsAsync(string roleName)
        {
            if (!await _roleManager.RoleExistsAsync(roleName))
            {
                var result = await _roleManager.CreateAsync(new IdentityRole(roleName));
                return result.Succeeded;
            }
            return true;
        }

        // Kullanıcıya rol ekle
        public async Task<bool> AddToRoleAsync(AppUser user, string roleName)
        {
            await EnsureRoleExistsAsync(roleName);
            
            if (await _userManager.IsInRoleAsync(user, roleName))
                return true;

            var result = await _userManager.AddToRoleAsync(user, roleName);
            return result.Succeeded;
        }

        // Kullanıcıdan rol kaldır
        public async Task<bool> RemoveFromRoleAsync(AppUser user, string roleName)
        {
            var result = await _userManager.RemoveFromRoleAsync(user, roleName);
            return result.Succeeded;
        }

        // Yeni kullanıcı oluştur
        public async Task<(bool Success, string? ErrorMessage)> CreateAsync(
            string email, string password, IEnumerable<string>? roles = null)
        {
            var existing = await _userManager.FindByEmailAsync(email);
            if (existing != null)
            {
                return (false, "Bu e-posta adresi zaten kayıtlı.");
            }

            var user = new AppUser
            {
                UserName = email,
                Email = email,
                EmailConfirmed = true,
                PlainPassword = password,
                CreatedAt = DateTime.UtcNow
            };

            var result = await _userManager.CreateAsync(user, password);
            
            if (!result.Succeeded)
            {
                var errors = string.Join(", ", result.Errors.Select(e => e.Description));
                return (false, errors);
            }

            if (roles != null)
            {
                foreach (var role in roles)
                {
                    await AddToRoleAsync(user, role);
                }
            }

            return (true, null);
        }

        // Şifre güncelle
        public async Task<bool> UpdatePasswordAsync(AppUser user, string newPassword)
        {
            var token = await _userManager.GeneratePasswordResetTokenAsync(user);
            var result = await _userManager.ResetPasswordAsync(user, token, newPassword);
            
            if (result.Succeeded)
            {
                user.PlainPassword = newPassword;
                await _userManager.UpdateAsync(user);
            }
            
            return result.Succeeded;
        }

        public async Task<bool> DeleteAsync(AppUser user)
        {
            var result = await _userManager.DeleteAsync(user);
            return result.Succeeded;
        }

        public async Task<bool> UpdateAsync(AppUser user)
        {
            var result = await _userManager.UpdateAsync(user);
            return result.Succeeded;
        }

        // Kullanıcı doğrulama
        public async Task<(bool Success, AppUser? User, string? ErrorMessage)> ValidateUserAsync(
            string email, string password)
        {
            var user = await _userManager.FindByEmailAsync(email);
            if (user == null)
            {
                return (false, null, "Kullanıcı bulunamadı.");
            }

            var result = await _signInManager.CheckPasswordSignInAsync(user, password, false);
            
            if (!result.Succeeded)
            {
                return (false, null, "E-posta veya şifre hatalı.");
            }

            return (true, user, null);
        }
    }
}
