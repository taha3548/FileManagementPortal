// ============================================
// ADMIN CONTROLLER - YÖNETİCİ PANELİ
// ============================================
// ASP.NET Identity ile kullanıcı/rol yönetimi
// UserManager: Kullanıcı CRUD işlemleri
// RoleManager: Rol atama/kaldırma
// Repository Pattern: Veri erişim katmanı
// [Authorize(Roles = "Admin")]: Sadece admin erişimi
// ============================================

using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using FileManagementPortal.Migrations;
using FileManagementPortal.Repositories;
using FileManagementPortal.Models;
using FileManagementPortal.Services;
using Microsoft.EntityFrameworkCore;

namespace FileManagementPortal.Controllers
{
    // ============================================
    // DEPENDENCY INJECTION - Servis enjeksiyonu
    // Repository Pattern ile veri erişimi
    // ============================================
    [Authorize(Roles = "Admin")] // Sadece Admin rolü erişebilir
    public class AdminController : Controller
    {
        // ASP.NET Identity servisleri
        private readonly UserManager<AppUser> _userManager;     // Kullanıcı yönetimi
        private readonly RoleManager<IdentityRole> _roleManager; // Rol yönetimi
        
        // Repository Pattern - Veri erişim katmanı
        private readonly IFileRepository _fileRepository;
        private readonly ICategoryRepository _categoryRepository;
        private readonly AppDbContext _context;
        
        // Diğer servisler
        private readonly IWebHostEnvironment _webHostEnvironment;
        private readonly ILogger<AdminController> _logger;

        public AdminController(
            UserManager<AppUser> userManager,
            RoleManager<IdentityRole> roleManager,
            IFileRepository fileRepository,
            ICategoryRepository categoryRepository,
            AppDbContext context,
            IWebHostEnvironment webHostEnvironment,
            ILogger<AdminController> logger)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _fileRepository = fileRepository;
            _categoryRepository = categoryRepository;
            _context = context;
            _webHostEnvironment = webHostEnvironment;
            _logger = logger;
        }

        // Süper Admin kontrolü - admin@gmail.com
        private bool IsSuperAdmin()
        {
            var currentUserEmail = User.Identity?.Name?.ToLower();
            return currentUserEmail == "admin@gmail.com";
        }

        // ============================================
        // DASHBOARD - Ana yönetim paneli sayfası
        // İstatistikler ve özet bilgiler
        // ============================================
        public async Task<IActionResult> Dashboard()
        {
            // Repository Pattern ile veri çekme
            var totalFiles = await _fileRepository.CountAsync();
            var totalCategories = await _categoryRepository.CountAsync();
            var totalUsers = await _userManager.Users.CountAsync();
            var totalFileSize = (await _fileRepository.GetAllAsync()).Sum(f => f.FileSize);
            var recentFiles = await _fileRepository.GetLatestAsync(10);
            var mostDownloadedFiles = await _fileRepository.GetMostDownloadedAsync(10);
            
            // Admin sayısını hesapla - Identity UserManager kullanımı
            var allUsers = await _userManager.Users.ToListAsync();
            var totalAdmins = 0;
            foreach (var user in allUsers)
            {
                if (await _userManager.IsInRoleAsync(user, "Admin"))
                    totalAdmins++;
            }

            // ViewModel oluştur ve view'a gönder
            var model = new FileManagementPortal.ViewModels.AdminDashboardViewModel
            {
                TotalFileCount = totalFiles,
                TotalCategoryCount = totalCategories,
                TotalUserCount = totalUsers,
                TotalAdminCount = totalAdmins,
                TotalFileSize = totalFileSize,
                RecentlyUploadedFiles = recentFiles,
                MostDownloadedFiles = mostDownloadedFiles
            };

            return View(model);
        }

        // ============================================
        // DOSYA YÖNETİMİ - Admin dosya listesi
        // Entity Framework Include ile ilişkili veriler
        // ============================================
        public async Task<IActionResult> Files()
        {
            // Entity Framework - Include ile kategorileri de getir
            var files = await _context.Files
                .Include(f => f.Categories)
                .OrderByDescending(f => f.UploadedAt)
                .ToListAsync();
            return View(files);
        }

        // ============================================
        // KATEGORİ YÖNETİMİ - CRUD işlemleri
        // Repository Pattern kullanımı
        // ============================================
        public async Task<IActionResult> Categories()
        {
            var categories = await _categoryRepository.GetAllAsync();
            return View(categories);
        }

        public IActionResult CreateCategory()
        {
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> CreateCategory(Category category)
        {
            if (ModelState.IsValid)
            {
                category.CreatedAt = DateTime.Now;
                await _categoryRepository.AddAsync(category);
                await _categoryRepository.SaveChangesAsync();
                TempData["SuccessMessage"] = "Kategori başarıyla oluşturuldu.";
                return RedirectToAction(nameof(Categories));
            }
            return View(category);
        }

        public async Task<IActionResult> EditCategory(int? id)
        {
            if (id == null) return NotFound();

            var category = await _categoryRepository.GetByIdAsync(id.Value);
            if (category == null) return NotFound();

            return View(category);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> EditCategory(int id, Category category)
        {
            if (id != category.Id) return NotFound();

            if (ModelState.IsValid)
            {
                try
                {
                    _categoryRepository.Update(category);
                    await _categoryRepository.SaveChangesAsync();
                    TempData["SuccessMessage"] = "Kategori başarıyla güncellendi.";
                    return RedirectToAction(nameof(Categories));
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Error updating category");
                    ModelState.AddModelError("", "Kategori güncellenirken bir hata oluştu.");
                }
            }
            return View(category);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> DeleteCategory(int id)
        {
            var category = await _categoryRepository.GetByIdAsync(id);
            if (category != null)
            {
                var fileCount = await _context.Files
                    .Where(f => f.Categories.Any(c => c.Id == id))
                    .CountAsync();
                
                if (fileCount > 0)
                {
                    TempData["ErrorMessage"] = "Bu kategoriye ait dosyalar olduğu için silinemez.";
                    return RedirectToAction(nameof(Categories));
                }

                _categoryRepository.Remove(category);
                await _categoryRepository.SaveChangesAsync();
                TempData["SuccessMessage"] = "Kategori başarıyla silindi.";
            }
            return RedirectToAction(nameof(Categories));
        }

        // ============================================
        // KULLANICI YÖNETİMİ - Identity UserManager
        // Rol bazlı sıralama ve yetkilendirme
        // ============================================
        public async Task<IActionResult> Users()
        {
            // Tüm kullanıcıları getir - Identity UserManager
            var allUsers = await _userManager.Users.ToListAsync();
            
            // Kullanıcıları sırala: Site Admin > Adminler > User'lar
            var sortedUsers = new List<AppUser>();
            var siteAdmin = new List<AppUser>();
            var admins = new List<AppUser>();
            var normalUsers = new List<AppUser>();
            
            // Rol kontrolü ile sınıflandırma
            foreach (var user in allUsers)
            {
                if (user.Email?.ToLower() == "admin@gmail.com")
                {
                    siteAdmin.Add(user);
                }
                else if (await _userManager.IsInRoleAsync(user, "Admin"))
                {
                    admins.Add(user);
                }
                else
                {
                    normalUsers.Add(user);
                }
            }
            
            // Sıralama: Site Admin en üstte, sonra Adminler, sonra User'lar
            sortedUsers.AddRange(siteAdmin);
            sortedUsers.AddRange(admins.OrderBy(u => u.Email));
            sortedUsers.AddRange(normalUsers.OrderBy(u => u.Email));
            
            return View(sortedUsers);
        }

        // Kullanıcı detay
        public async Task<IActionResult> UserDetail(string? id)
        {
            if (string.IsNullOrEmpty(id)) return NotFound();

            var user = await _userManager.FindByIdAsync(id);
            if (user == null) return NotFound();

            var isSuperAdmin = IsSuperAdmin();
            var userRoles = await _userManager.GetRolesAsync(user);
            var isTargetUserAdmin = userRoles.Contains("Admin");

            if (isTargetUserAdmin && !isSuperAdmin)
            {
                TempData["ErrorMessage"] = "Bu admin kullanıcısını görüntüleme yetkiniz yok.";
                return RedirectToAction(nameof(Users));
            }

            var files = await _context.Files
                .Where(f => f.UploaderUserId == user.Id)
                .Include(f => f.Categories)
                .OrderByDescending(f => f.UploadedAt)
                .ToListAsync();

            var logs = await _context.UserLogs
                .Where(l => l.UserId == user.Id)
                .OrderByDescending(l => l.Date)
                .Take(50)
                .ToListAsync();

            var totalFileSize = files.Sum(f => f.FileSize);
            var canViewPassword = isSuperAdmin || !isTargetUserAdmin;

            // Get plain password from database
            var plainPassword = canViewPassword ? user.PlainPassword : null;

            var model = new FileManagementPortal.ViewModels.UserDetailViewModel
            {
                Id = user.Id,
                Email = user.Email ?? string.Empty,
                UserName = user.UserName ?? string.Empty,
                Roles = userRoles.ToList(),
                EmailConfirmed = user.EmailConfirmed,
                TotalFileCount = files.Count,
                TotalFileSize = totalFileSize,
                Files = files,
                Logs = logs,
                CanViewPassword = canViewPassword,
                PlainPassword = plainPassword
            };

            return View(model);
        }

        // Şifre değiştirme
        public async Task<IActionResult> ChangeUserPassword(string? id)
        {
            if (string.IsNullOrEmpty(id)) return NotFound();

            var user = await _userManager.FindByIdAsync(id);
            if (user == null) return NotFound();

            if (user.Email?.ToLower() == "admin@gmail.com")
            {
                TempData["ErrorMessage"] = "Standart admin hesabının şifresi değiştirilemez.";
                return RedirectToAction(nameof(UserDetail), new { id });
            }

            ViewBag.UserId = user.Id;
            ViewBag.UserEmail = user.Email;
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ChangeUserPassword(string userId, string newPassword, string confirmPassword)
        {
            if (string.IsNullOrEmpty(userId)) return NotFound();

            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
            {
                TempData["ErrorMessage"] = "Kullanıcı bulunamadı.";
                return RedirectToAction(nameof(Users));
            }

            var isSuperAdmin = IsSuperAdmin();
            var userRoles = await _userManager.GetRolesAsync(user);
            var isTargetUserAdmin = userRoles.Contains("Admin");

            if (isTargetUserAdmin && !isSuperAdmin)
            {
                TempData["ErrorMessage"] = "Admin kullanıcılarının şifresini değiştirme yetkiniz yok.";
                return RedirectToAction(nameof(Users));
            }

            if (user.Email?.ToLower() == "admin@gmail.com")
            {
                TempData["ErrorMessage"] = "Süper admin hesabının şifresi değiştirilemez.";
                return RedirectToAction(nameof(UserDetail), new { id = userId });
            }

            if (string.IsNullOrEmpty(newPassword) || newPassword.Length < 6)
            {
                TempData["ErrorMessage"] = "Şifre en az 6 karakter olmalıdır.";
                ViewBag.UserId = user.Id;
                ViewBag.UserEmail = user.Email;
                return View();
            }

            if (newPassword != confirmPassword)
            {
                TempData["ErrorMessage"] = "Şifreler eşleşmiyor.";
                ViewBag.UserId = user.Id;
                ViewBag.UserEmail = user.Email;
                return View();
            }

            try
            {
                // Identity ile şifre sıfırlama
                var token = await _userManager.GeneratePasswordResetTokenAsync(user);
                var result = await _userManager.ResetPasswordAsync(user, token, newPassword);
                
                if (result.Succeeded)
                {
                    user.PlainPassword = newPassword;
                    await _userManager.UpdateAsync(user);
                    TempData["SuccessMessage"] = $"{user.Email} kullanıcısının şifresi başarıyla değiştirildi.";
                    return RedirectToAction(nameof(UserDetail), new { id = userId });
                }
                else
                {
                    TempData["ErrorMessage"] = string.Join(", ", result.Errors.Select(e => e.Description));
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error changing password");
                TempData["ErrorMessage"] = "Şifre değiştirilirken bir hata oluştu.";
            }

            ViewBag.UserId = user.Id;
            ViewBag.UserEmail = user.Email;
            return View();
        }

        // Kullanıcı silme
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> DeleteUser(string id)
        {
            if (string.IsNullOrEmpty(id)) return NotFound();

            var user = await _userManager.FindByIdAsync(id);
            if (user == null)
            {
                TempData["ErrorMessage"] = "Kullanıcı bulunamadı.";
                return RedirectToAction(nameof(Users));
            }

            var isSuperAdmin = IsSuperAdmin();
            var userRoles = await _userManager.GetRolesAsync(user);
            var isTargetUserAdmin = userRoles.Contains("Admin");

            if (isTargetUserAdmin && !isSuperAdmin)
            {
                TempData["ErrorMessage"] = "Admin kullanıcıları silme yetkiniz yok.";
                return RedirectToAction(nameof(Users));
            }

            if (user.Email?.ToLower() == "admin@gmail.com")
            {
                TempData["ErrorMessage"] = "Süper admin hesabı silinemez.";
                return RedirectToAction(nameof(Users));
            }

            try
            {
                var result = await _userManager.DeleteAsync(user);
                if (result.Succeeded)
                {
                    TempData["SuccessMessage"] = "Kullanıcı başarıyla silindi.";
                }
                else
                {
                    TempData["ErrorMessage"] = string.Join(", ", result.Errors.Select(e => e.Description));
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error deleting user");
                TempData["ErrorMessage"] = "Kullanıcı silinirken bir hata oluştu.";
            }

            return RedirectToAction(nameof(Users));
        }

        // ============================================
        // ROL YÖNETİMİ - Identity RoleManager
        // Admin rolü ekleme - Otomatik rol değişimi
        // ============================================
        [HttpPost]
        [ValidateAntiForgeryToken] // CSRF koruması
        public async Task<IActionResult> AddAdminRole(string id)
        {
            if (string.IsNullOrEmpty(id)) return NotFound();

            // Sadece süper admin rol yönetimi yapabilir
            if (!IsSuperAdmin())
            {
                TempData["ErrorMessage"] = "Admin rollerini yönetme yetkiniz yok.";
                return RedirectToAction(nameof(Users));
            }

            var user = await _userManager.FindByIdAsync(id);
            if (user == null)
            {
                TempData["ErrorMessage"] = "Kullanıcı bulunamadı.";
                return RedirectToAction(nameof(Users));
            }

            if (user.Email?.ToLower() == "admin@gmail.com")
            {
                TempData["ErrorMessage"] = "Süper admin hesabının rolleri değiştirilemez.";
                return RedirectToAction(nameof(UserDetail), new { id });
            }

            try
            {
                // Admin rolü ekle - Identity UserManager
                await _userManager.AddToRoleAsync(user, "Admin");
                
                // User rolünü otomatik kaldır - Rol değişimi
                if (await _userManager.IsInRoleAsync(user, "User"))
                {
                    await _userManager.RemoveFromRoleAsync(user, "User");
                }
                
                TempData["SuccessMessage"] = "Admin rolü eklendi ve User rolü kaldırıldı.";
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error adding admin role");
                TempData["ErrorMessage"] = "Admin rolü eklenirken bir hata oluştu.";
            }

            return RedirectToAction(nameof(UserDetail), new { id });
        }

        // Admin rolü kaldır
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> RemoveAdminRole(string id)
        {
            if (string.IsNullOrEmpty(id)) return NotFound();

            if (!IsSuperAdmin())
            {
                TempData["ErrorMessage"] = "Admin rollerini yönetme yetkiniz yok.";
                return RedirectToAction(nameof(Users));
            }

            var user = await _userManager.FindByIdAsync(id);
            if (user == null)
            {
                TempData["ErrorMessage"] = "Kullanıcı bulunamadı.";
                return RedirectToAction(nameof(Users));
            }

            if (user.Email?.ToLower() == "admin@gmail.com")
            {
                TempData["ErrorMessage"] = "Süper admin hesabının rolleri değiştirilemez.";
                return RedirectToAction(nameof(UserDetail), new { id });
            }

            try
            {
                await _userManager.RemoveFromRoleAsync(user, "Admin");
                
                // Admin rolü kaldırılınca otomatik User rolü ekle
                if (!await _userManager.IsInRoleAsync(user, "User"))
                {
                    await _userManager.AddToRoleAsync(user, "User");
                }
                
                TempData["SuccessMessage"] = "Admin rolü kaldırıldı ve User rolü eklendi.";
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error removing admin role");
                TempData["ErrorMessage"] = "Admin rolü kaldırılırken bir hata oluştu.";
            }

            return RedirectToAction(nameof(UserDetail), new { id });
        }

        // User rolü ekle
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> AddUserRole(string id)
        {
            if (string.IsNullOrEmpty(id)) return NotFound();

            var user = await _userManager.FindByIdAsync(id);
            if (user == null)
            {
                TempData["ErrorMessage"] = "Kullanıcı bulunamadı.";
                return RedirectToAction(nameof(Users));
            }

            if (user.Email?.ToLower() == "admin@gmail.com")
            {
                TempData["ErrorMessage"] = "Standart admin hesabının rolleri değiştirilemez.";
                return RedirectToAction(nameof(UserDetail), new { id });
            }

            try
            {
                // User rolü ekle
                await _userManager.AddToRoleAsync(user, "User");
                
                // Admin rolünü otomatik kaldır
                if (await _userManager.IsInRoleAsync(user, "Admin"))
                {
                    await _userManager.RemoveFromRoleAsync(user, "Admin");
                }
                
                TempData["SuccessMessage"] = "User rolü eklendi.";
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error adding user role");
                TempData["ErrorMessage"] = "Kullanıcı rolü eklenirken bir hata oluştu.";
            }

            return RedirectToAction(nameof(UserDetail), new { id });
        }

        // User rolü kaldır
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> RemoveUserRole(string id)
        {
            if (string.IsNullOrEmpty(id)) return NotFound();

            var user = await _userManager.FindByIdAsync(id);
            if (user == null)
            {
                TempData["ErrorMessage"] = "Kullanıcı bulunamadı.";
                return RedirectToAction(nameof(Users));
            }

            if (user.Email?.ToLower() == "admin@gmail.com")
            {
                TempData["ErrorMessage"] = "Standart admin hesabının rolleri değiştirilemez.";
                return RedirectToAction(nameof(UserDetail), new { id });
            }

            try
            {
                // User rolü kaldır
                await _userManager.RemoveFromRoleAsync(user, "User");
                
                // Admin rolünü otomatik ekle
                if (!await _userManager.IsInRoleAsync(user, "Admin"))
                {
                    await _userManager.AddToRoleAsync(user, "Admin");
                }
                
                TempData["SuccessMessage"] = "User rolü kaldırıldı ve Admin rolü eklendi.";
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error removing user role");
                TempData["ErrorMessage"] = "Kullanıcı rolü kaldırılırken bir hata oluştu.";
            }

            return RedirectToAction(nameof(UserDetail), new { id });
        }
    }
}
