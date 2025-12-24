// ============================================
// HOME CONTROLLER - Ana Sayfa ve Profil
// ============================================
// Kullanıcı ara yüzü (Genel arayüz)
// Profil yönetimi ve şifre değiştirme
// ============================================

using System.Diagnostics;
using FileManagementPortal.Models;
using FileManagementPortal.Repositories;
using FileManagementPortal.Services;
using FileManagementPortal.Migrations;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using System.Security.Claims;

namespace FileManagementPortal.Controllers
{
    public class HomeController : Controller
    {
        private readonly ILogger<HomeController> _logger;
        private readonly IFileRepository _fileRepository;
        private readonly ICategoryRepository _categoryRepository;
        private readonly ICustomUserService _userService;
        private readonly AppDbContext _context;

        public HomeController(
            ILogger<HomeController> logger,
            IFileRepository fileRepository,
            ICategoryRepository categoryRepository,
            ICustomUserService userService,
            AppDbContext context)
        {
            _logger = logger;
            _fileRepository = fileRepository;
            _categoryRepository = categoryRepository;
            _userService = userService;
            _context = context;
        }

        // Ana sayfa - Kullanıcı rolüne göre dosyalar
        public async Task<IActionResult> Index()
        {
            var currentUserId = User.FindFirstValue(ClaimTypes.NameIdentifier);
            var isAdmin = User.IsInRole("Admin");

            if (isAdmin)
            {
                // Admin tüm dosyaları görür
                ViewBag.RecentlyUploadedFiles = await _fileRepository.GetLatestAsync(6);
                ViewBag.MostDownloadedFiles = await _fileRepository.GetMostDownloadedAsync(6);
            }
            else if (User.Identity?.IsAuthenticated == true && !string.IsNullOrEmpty(currentUserId))
            {
                // Normal kullanıcı sadece kendi dosyalarını görür
                var userFiles = (await _fileRepository.GetUserFilesAsync(currentUserId)).ToList();
                
                ViewBag.RecentlyUploadedFiles = userFiles
                    .OrderByDescending(f => f.UploadedAt)
                    .Take(6);
                
                ViewBag.MostDownloadedFiles = userFiles
                    .OrderByDescending(f => f.DownloadCount)
                    .Take(6);
            }
            else
            {
                ViewBag.RecentlyUploadedFiles = Enumerable.Empty<FileItem>();
                ViewBag.MostDownloadedFiles = Enumerable.Empty<FileItem>();
            }

            return View();
        }

        public IActionResult Privacy()
        {
            return View();
        }

        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }

        // Profil sayfası
        [Authorize]
        public async Task<IActionResult> Profile()
        {
            var currentUserId = User.FindFirstValue(ClaimTypes.NameIdentifier);
            if (string.IsNullOrEmpty(currentUserId))
            {
                return RedirectToAction("Login", "Account");
            }

            var user = await _userService.FindByIdAsync(currentUserId);
            if (user == null)
            {
                return NotFound();
            }

            var model = new FileManagementPortal.ViewModels.UserProfileViewModel
            {
                Id = user.Id,
                Email = user.Email ?? string.Empty,
                UserName = user.UserName
            };

            return View(model);
        }

        // E-posta güncelleme
        [Authorize]
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> UpdateEmail(string newEmail)
        {
            var currentUserId = User.FindFirstValue(ClaimTypes.NameIdentifier);
            if (string.IsNullOrEmpty(currentUserId))
            {
                return RedirectToAction("Login", "Account");
            }

            if (string.IsNullOrEmpty(newEmail) || !newEmail.Contains("@"))
            {
                TempData["ErrorMessage"] = "Geçerli bir e-posta adresi girin.";
                return RedirectToAction(nameof(Profile));
            }

            var user = await _userService.FindByIdAsync(currentUserId);
            if (user == null)
            {
                TempData["ErrorMessage"] = "Kullanıcı bulunamadı.";
                return RedirectToAction(nameof(Profile));
            }

            var existingUser = await _userService.FindByEmailAsync(newEmail);
            if (existingUser != null && existingUser.Id != user.Id)
            {
                TempData["ErrorMessage"] = "Bu e-posta adresi zaten kullanılıyor.";
                return RedirectToAction(nameof(Profile));
            }

            try
            {
                user.Email = newEmail;
                user.UserName = newEmail;
                _context.Users.Update(user);
                await _context.SaveChangesAsync();

                TempData["SuccessMessage"] = "E-posta adresi başarıyla güncellendi.";
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "E-posta güncelleme hatası");
                TempData["ErrorMessage"] = "E-posta güncellenirken bir hata oluştu.";
            }

            return RedirectToAction(nameof(Profile));
        }

        // Şifre değiştirme
        [Authorize]
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ChangePassword(string currentPassword, string newPassword, string confirmPassword)
        {
            var currentUserId = User.FindFirstValue(ClaimTypes.NameIdentifier);
            if (string.IsNullOrEmpty(currentUserId))
            {
                return RedirectToAction("Login", "Account");
            }

            var user = await _userService.FindByIdAsync(currentUserId);
            if (user == null)
            {
                TempData["ErrorMessage"] = "Kullanıcı bulunamadı.";
                return RedirectToAction(nameof(Profile));
            }

            var validation = await _userService.ValidateUserAsync(user.Email ?? string.Empty, currentPassword);
            if (!validation.Success)
            {
                TempData["ErrorMessage"] = "Mevcut şifre yanlış.";
                return RedirectToAction(nameof(Profile));
            }

            if (string.IsNullOrEmpty(newPassword) || newPassword.Length < 6)
            {
                TempData["ErrorMessage"] = "Yeni şifre en az 6 karakter olmalıdır.";
                return RedirectToAction(nameof(Profile));
            }

            if (newPassword != confirmPassword)
            {
                TempData["ErrorMessage"] = "Şifreler eşleşmiyor.";
                return RedirectToAction(nameof(Profile));
            }

            try
            {
                await _userService.UpdatePasswordAsync(user, newPassword);
                TempData["SuccessMessage"] = "Şifre başarıyla değiştirildi.";
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Şifre değiştirme hatası");
                TempData["ErrorMessage"] = "Şifre değiştirilirken bir hata oluştu.";
            }

            return RedirectToAction(nameof(Profile));
        }
    }
}
