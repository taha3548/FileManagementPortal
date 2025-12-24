// ============================================
// ACCOUNT CONTROLLER - Kimlik Doğrulama
// ============================================
// ASP.NET Identity ile üyelik sistemi
// Cookie bazlı oturum açma/kapama
// Kullanıcı kayıt ve giriş işlemleri
// ============================================

using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using FileManagementPortal.Models;
using FileManagementPortal.ViewModels;

namespace FileManagementPortal.Controllers
{
    public class AccountController : Controller
    {
        // ASP.NET Identity servisleri
        private readonly SignInManager<AppUser> _signInManager;  // Oturum yönetimi
        private readonly UserManager<AppUser> _userManager;      // Kullanıcı CRUD
        private readonly ILogger<AccountController> _logger;

        public AccountController(
            SignInManager<AppUser> signInManager,
            UserManager<AppUser> userManager,
            ILogger<AccountController> logger)
        {
            _signInManager = signInManager;
            _userManager = userManager;
            _logger = logger;
        }

        // GET: Giriş sayfası
        [HttpGet]
        [AllowAnonymous]
        public IActionResult Login(string? returnUrl = null)
        {
            if (User.Identity?.IsAuthenticated == true)
            {
                return RedirectToLocal(returnUrl);
            }
            return View(new LoginViewModel { ReturnUrl = returnUrl });
        }

        // POST: Giriş işlemi - Identity PasswordSignInAsync
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Login(LoginViewModel model)
        {
            if (!ModelState.IsValid)
            {
                return View(model);
            }

            var user = await _userManager.FindByEmailAsync(model.Email);
            if (user == null)
            {
                ModelState.AddModelError(string.Empty, "E-posta veya şifre hatalı.");
                return View(model);
            }

            // Cookie bazlı oturum açma
            var result = await _signInManager.PasswordSignInAsync(
                user,
                model.Password,
                model.RememberMe,
                lockoutOnFailure: false);

            if (result.Succeeded)
            {
                _logger.LogInformation("User logged in: {Email}", model.Email);
                return RedirectToLocal(model.ReturnUrl);
            }

            if (result.IsLockedOut)
            {
                ModelState.AddModelError(string.Empty, "Hesabınız kilitlendi.");
                return View(model);
            }

            ModelState.AddModelError(string.Empty, "E-posta veya şifre hatalı.");
            return View(model);
        }

        // POST: Çıkış işlemi
        [HttpPost]
        [Authorize]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Logout()
        {
            await _signInManager.SignOutAsync();
            return RedirectToAction("Index", "Home");
        }

        [HttpGet]
        [AllowAnonymous]
        public IActionResult AccessDenied()
        {
            return View();
        }

        // GET: Kayıt sayfası
        [HttpGet]
        [AllowAnonymous]
        public IActionResult Register()
        {
            return View(new LoginViewModel());
        }

        // POST: Kayıt işlemi - Identity CreateAsync
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Register(LoginViewModel model)
        {
            if (!ModelState.IsValid)
            {
                return View(model);
            }

            if (model.Password != model.ConfirmPassword)
            {
                ModelState.AddModelError(string.Empty, "Şifreler eşleşmiyor.");
                return View(model);
            }

            var user = new AppUser
            {
                UserName = model.Email,
                Email = model.Email,
                EmailConfirmed = true,
                PlainPassword = model.Password,
                CreatedAt = DateTime.UtcNow
            };

            // Kullanıcı oluştur (şifre otomatik hashlenir)
            var result = await _userManager.CreateAsync(user, model.Password);

            if (result.Succeeded)
            {
                // User rolü ata
                await _userManager.AddToRoleAsync(user, "User");
                
                TempData["SuccessMessage"] = "Kayıt başarılı! Lütfen giriş yapın.";
                return RedirectToAction("Login");
            }

            foreach (var error in result.Errors)
            {
                ModelState.AddModelError(string.Empty, error.Description);
            }

            return View(model);
        }

        private IActionResult RedirectToLocal(string? returnUrl)
        {
            if (!string.IsNullOrEmpty(returnUrl) && Url.IsLocalUrl(returnUrl))
            {
                return Redirect(returnUrl);
            }
            return RedirectToAction("Index", "Home");
        }
    }
}
