// ============================================
// DOSYA CONTROLLER - Dosya İşlemleri
// Dosya yükleme, indirme, listeleme, silme
// AJAX ile dosya silme (Delete metodu)
// Repository Pattern ile veri erişimi
// ============================================

using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using FileManagementPortal.Repositories;
using FileManagementPortal.ViewModels;
using FileManagementPortal.Services;
using FileManagementPortal.Models;
using System.Security.Claims;

namespace FileManagementPortal.Controllers
{
    public class FileController : Controller
    {
        private readonly UserManager<AppUser> _userManager;
        private readonly IFileRepository _fileRepository;        // Repository Pattern
        private readonly ICategoryRepository _categoryRepository;
        private readonly IWebHostEnvironment _webHostEnvironment;
        private readonly ILogService _logService;
        private readonly ILogger<FileController> _logger;

        public FileController(
            UserManager<AppUser> userManager,
            IFileRepository fileRepository,
            ICategoryRepository categoryRepository,
            IWebHostEnvironment webHostEnvironment,
            ILogService logService,
            ILogger<FileController> logger)
        {
            _userManager = userManager;
            _fileRepository = fileRepository;
            _categoryRepository = categoryRepository;
            _webHostEnvironment = webHostEnvironment;
            _logService = logService;
            _logger = logger;
        }

        private bool IsSuperAdmin()
        {
            return User.Identity?.Name?.ToLower() == "admin@gmail.com";
        }

        // GET: Dosya listesi (Kullanıcı ara yüzü)
        [Authorize]
        public async Task<IActionResult> Index(int? categoryId, string? search)
        {
            var viewModel = new FileListViewModel
            {
                Categories = await _categoryRepository.GetActiveCategoriesAsync(),
                SelectedCategoryId = categoryId,
                SearchTerm = search
            };

            var currentUserId = User.FindFirstValue(ClaimTypes.NameIdentifier) ?? string.Empty;
            var isAdmin = User.IsInRole("Admin");

            IEnumerable<FileItem> files;

            if (isAdmin)
            {
                var isSuperAdmin = IsSuperAdmin();

                if (categoryId.HasValue && categoryId.Value > 0)
                {
                    files = await _fileRepository.GetFilesByCategoryAsync(categoryId.Value);
                }
                else if (!string.IsNullOrEmpty(search))
                {
                    var allFiles = await _fileRepository.GetActiveFilesAsync();
                    files = allFiles.Where(d =>
                        d.FileName.Contains(search, StringComparison.OrdinalIgnoreCase) ||
                        (d.Description != null && d.Description.Contains(search, StringComparison.OrdinalIgnoreCase))
                    );
                }
                else
                {
                    files = await _fileRepository.GetActiveFilesAsync();
                }

                if (!isSuperAdmin)
                {
                    var filteredFiles = new List<FileItem>();
                    foreach (var file in files)
                    {
                        if (!string.IsNullOrEmpty(file.UploaderUserId))
                        {
                            var fileOwner = await _userManager.FindByIdAsync(file.UploaderUserId);
                            if (fileOwner != null && await _userManager.IsInRoleAsync(fileOwner, "Admin"))
                            {
                                continue;
                            }
                        }
                        filteredFiles.Add(file);
                    }
                    files = filteredFiles;
                }
            }
            else
            {
                if (categoryId.HasValue && categoryId.Value > 0)
                {
                    var userFiles = await _fileRepository.GetUserFilesAsync(currentUserId);
                    files = userFiles.Where(d => d.Categories.Any(k => k.Id == categoryId.Value));
                }
                else if (!string.IsNullOrEmpty(search))
                {
                    var userFiles = await _fileRepository.GetUserFilesAsync(currentUserId);
                    files = userFiles.Where(d =>
                        d.FileName.Contains(search, StringComparison.OrdinalIgnoreCase) ||
                        (d.Description != null && d.Description.Contains(search, StringComparison.OrdinalIgnoreCase))
                    );
                }
                else
                {
                    files = await _fileRepository.GetUserFilesAsync(currentUserId);
                }
            }

            viewModel.Files = files;
            return View(viewModel);
        }

        // GET: Dosya detay
        [Authorize]
        public async Task<IActionResult> Details(int? id)
        {
            if (id == null) return NotFound();

            var file = await _fileRepository.GetFileDetailAsync(id.Value);
            if (file == null || !file.IsActive) return NotFound();

            var currentUserId = User.FindFirstValue(ClaimTypes.NameIdentifier) ?? string.Empty;
            var isAdmin = User.IsInRole("Admin");

            if (!isAdmin && (string.IsNullOrEmpty(currentUserId) || file.UploaderUserId != currentUserId))
            {
                return Forbid();
            }

            if (isAdmin && !string.IsNullOrEmpty(file.UploaderUserId))
            {
                var fileOwner = await _userManager.FindByIdAsync(file.UploaderUserId);
                if (fileOwner != null && await _userManager.IsInRoleAsync(fileOwner, "Admin") && !IsSuperAdmin())
                {
                    return Forbid();
                }
            }

            IEnumerable<FileItem> similarFiles;
            if (isAdmin)
            {
                if (file.Categories != null && file.Categories.Any())
                {
                    var firstCategoryId = file.Categories.First().Id;
                    similarFiles = (await _fileRepository.GetFilesByCategoryAsync(firstCategoryId))
                        .Where(d => d.Id != file.Id && d.IsActive)
                        .Take(5);
                }
                else
                {
                    var allFiles = await _fileRepository.GetActiveFilesAsync();
                    similarFiles = allFiles.Where(d => d.Id != file.Id).Take(5);
                }
            }
            else
            {
                var userFiles = await _fileRepository.GetUserFilesAsync(currentUserId);
                var fileCategoryIds = file.Categories?.Select(k => k.Id).ToList() ?? new List<int>();
                similarFiles = userFiles
                    .Where(d => d.Id != file.Id && d.Categories != null &&
                                d.Categories.Any(k => fileCategoryIds.Contains(k.Id)))
                    .Take(5);
            }

            var viewModel = new FileDetailViewModel
            {
                File = file,
                SimilarFiles = similarFiles
            };

            return View(viewModel);
        }

        // GET: Dosya yükleme formu
        [Authorize]
        public async Task<IActionResult> Create()
        {
            var activeCategories = await _categoryRepository.GetActiveCategoriesAsync();
            if (!activeCategories.Any())
            {
                TempData["ErrorMessage"] = "Aktif kategori bulunamadı.";
                return RedirectToAction(nameof(Index));
            }

            var viewModel = new FileViewModel
            {
                Categories = activeCategories.ToList()
            };
            return View(viewModel);
        }

        // POST: Dosya yükleme işlemi
        [HttpPost]
        [ValidateAntiForgeryToken]
        [Authorize]
        public async Task<IActionResult> Create(FileViewModel viewModel)
        {
            if (viewModel.CategoryIds == null || viewModel.CategoryIds.Count == 0)
            {
                ModelState.AddModelError("CategoryIds", "En az bir kategori seçmelisiniz.");
            }

            if (viewModel.File == null || viewModel.File.Length == 0)
            {
                ModelState.AddModelError("File", "Lütfen bir dosya seçin.");
            }

            if (ModelState.IsValid && viewModel.File != null && viewModel.File.Length > 0 && viewModel.CategoryIds != null && viewModel.CategoryIds.Count > 0)
            {
                try
                {
                    var selectedCategories = new List<Category>();
                    foreach (var categoryId in viewModel.CategoryIds)
                    {
                        var category = await _categoryRepository.GetByIdAsync(categoryId);
                        if (category == null || !category.IsActive)
                        {
                            ModelState.AddModelError("CategoryIds", $"Seçilen kategori geçersiz.");
                            viewModel.Categories = (await _categoryRepository.GetActiveCategoriesAsync()).ToList();
                            return View(viewModel);
                        }
                        selectedCategories.Add(category);
                    }

                    var uploadsFolder = Path.Combine(_webHostEnvironment.WebRootPath, "uploads");
                    if (!Directory.Exists(uploadsFolder))
                    {
                        Directory.CreateDirectory(uploadsFolder);
                    }

                    var safeFileName = Path.GetFileName(viewModel.File.FileName);
                    var uniqueFileName = Guid.NewGuid().ToString() + Path.GetExtension(safeFileName);
                    var filePath = Path.Combine(uploadsFolder, uniqueFileName);

                    var fullUploadsPath = Path.GetFullPath(uploadsFolder);
                    var fullFilePath = Path.GetFullPath(filePath);

                    if (!fullFilePath.StartsWith(fullUploadsPath, StringComparison.OrdinalIgnoreCase))
                    {
                        ModelState.AddModelError("File", "Geçersiz dosya yolu.");
                        viewModel.Categories = (await _categoryRepository.GetActiveCategoriesAsync()).ToList();
                        return View(viewModel);
                    }

                    using (var fileStream = new FileStream(fullFilePath, FileMode.Create))
                    {
                        await viewModel.File.CopyToAsync(fileStream);
                    }

                    var fileItem = new FileItem
                    {
                        FileName = viewModel.FileName,
                        Description = viewModel.Description,
                        FileSize = viewModel.File.Length,
                        FileType = Path.GetExtension(viewModel.File.FileName),
                        FilePath = $"/uploads/{uniqueFileName}",
                        UploadedAt = DateTime.Now,
                        UploaderUserId = User.FindFirstValue(ClaimTypes.NameIdentifier),
                        IsActive = true,
                        DownloadCount = 0,
                        Categories = selectedCategories
                    };

                    await _fileRepository.AddAsync(fileItem);
                    await _fileRepository.SaveChangesAsync();

                    // Log kaydı
                    var currentUserId = User.FindFirstValue(ClaimTypes.NameIdentifier);
                    var userEmail = User.Identity?.Name;
                    var ipAddress = HttpContext.Connection.RemoteIpAddress?.ToString();
                    await _logService.LogAsync(
                        currentUserId ?? "",
                        userEmail,
                        "FileUploaded",
                        $"Dosya yüklendi: {fileItem.FileName}",
                        fileItem.FileName,
                        fileItem.Id,
                        ipAddress
                    );

                    TempData["SuccessMessage"] = "Dosya başarıyla yüklendi.";
                    return RedirectToAction(nameof(Index));
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Dosya yükleme hatası");
                    ModelState.AddModelError("", "Dosya yüklenirken bir hata oluştu.");
                }
            }

            viewModel.Categories = (await _categoryRepository.GetActiveCategoriesAsync()).ToList();
            return View(viewModel);
        }

        // GET: Dosya indirme
        [Authorize]
        public async Task<IActionResult> Download(int? id)
        {
            if (id == null) return NotFound();

            var file = await _fileRepository.GetByIdAsync(id.Value);
            if (file == null || !file.IsActive || string.IsNullOrEmpty(file.FilePath))
            {
                return NotFound();
            }

            var currentUserId = User.FindFirstValue(ClaimTypes.NameIdentifier);
            var isAdmin = User.IsInRole("Admin");

            if (!isAdmin && (string.IsNullOrEmpty(currentUserId) || file.UploaderUserId != currentUserId))
            {
                return Forbid();
            }

            if (isAdmin && !string.IsNullOrEmpty(file.UploaderUserId))
            {
                var fileOwner = await _userManager.FindByIdAsync(file.UploaderUserId);
                if (fileOwner != null && await _userManager.IsInRoleAsync(fileOwner, "Admin") && !IsSuperAdmin())
                {
                    return Forbid();
                }
            }

            var relativePath = file.FilePath.TrimStart('/');
            var filePath = Path.Combine(_webHostEnvironment.WebRootPath, relativePath);

            var fullWebRootPath = Path.GetFullPath(_webHostEnvironment.WebRootPath);
            var fullFilePath = Path.GetFullPath(filePath);

            if (!fullFilePath.StartsWith(fullWebRootPath, StringComparison.OrdinalIgnoreCase))
            {
                return NotFound("Dosya bulunamadı.");
            }

            if (!System.IO.File.Exists(fullFilePath))
            {
                return NotFound();
            }

            await _fileRepository.IncrementDownloadCountAsync(file.Id);
            await _fileRepository.SaveChangesAsync();

            // Log kaydı
            var logUserId = User.FindFirstValue(ClaimTypes.NameIdentifier);
            var userEmail = User.Identity?.Name;
            var ipAddress = HttpContext.Connection.RemoteIpAddress?.ToString();
            await _logService.LogAsync(
                logUserId ?? "",
                userEmail,
                "FileDownloaded",
                $"Dosya indirildi: {file.FileName}",
                file.FileName,
                file.Id,
                ipAddress
            );

            var fileBytes = await System.IO.File.ReadAllBytesAsync(fullFilePath);
            return File(fileBytes, "application/octet-stream", file.FileName + file.FileType);
        }

        // GET: Dosya düzenleme formu
        [Authorize]
        public async Task<IActionResult> Edit(int? id)
        {
            if (id == null) return NotFound();

            var file = await _fileRepository.GetFileDetailAsync(id.Value);
            if (file == null || !file.IsActive) return NotFound();

            var currentUserId = User.FindFirstValue(ClaimTypes.NameIdentifier) ?? string.Empty;
            var isAdmin = User.IsInRole("Admin");

            if (!isAdmin && (string.IsNullOrEmpty(currentUserId) || file.UploaderUserId != currentUserId))
            {
                return Forbid();
            }

            var viewModel = new FileEditViewModel
            {
                Id = file.Id,
                FileName = file.FileName,
                Description = file.Description
            };

            return View(viewModel);
        }

        // POST: Dosya düzenleme işlemi
        [HttpPost]
        [ValidateAntiForgeryToken]
        [Authorize]
        public async Task<IActionResult> Edit(FileEditViewModel viewModel)
        {
            if (!ModelState.IsValid)
            {
                return View(viewModel);
            }

            var file = await _fileRepository.GetByIdAsync(viewModel.Id);
            if (file == null || !file.IsActive)
            {
                return NotFound();
            }

            var currentUserId = User.FindFirstValue(ClaimTypes.NameIdentifier) ?? string.Empty;
            var isAdmin = User.IsInRole("Admin");

            if (!isAdmin && (string.IsNullOrEmpty(currentUserId) || file.UploaderUserId != currentUserId))
            {
                return Forbid();
            }

            var oldFileName = file.FileName;
            file.FileName = viewModel.FileName;
            file.Description = viewModel.Description;

            _fileRepository.Update(file);
            await _fileRepository.SaveChangesAsync();

            // Log kaydı
            var logUserId = User.FindFirstValue(ClaimTypes.NameIdentifier);
            var userEmail = User.Identity?.Name;
            var ipAddress = HttpContext.Connection.RemoteIpAddress?.ToString();
            await _logService.LogAsync(
                logUserId ?? "",
                userEmail,
                "FileEdited",
                $"Dosya düzenlendi: {oldFileName} -> {file.FileName}",
                file.FileName,
                file.Id,
                ipAddress
            );

            TempData["SuccessMessage"] = "Dosya başarıyla güncellendi.";
            return RedirectToAction(nameof(Details), new { id = file.Id });
        }

        // ============================================
        // AJAX İLE DOSYA SİLME - JSON Response
        // Sayfa yenilenmeden silme işlemi
        // jQuery AJAX ile çalışır
        // ============================================
        [HttpPost]
        [Authorize]
        public async Task<IActionResult> Delete(int id)
        {
            try
            {
                // Repository Pattern ile dosya getir
                var file = await _fileRepository.GetByIdAsync(id);
                if (file == null)
                {
                    return Json(new { success = false, message = "Dosya bulunamadı." });
                }

                var currentUserId = User.FindFirstValue(ClaimTypes.NameIdentifier);
                var isAdmin = User.IsInRole("Admin");
                
                // Yetkilendirme kontrolü
                if (file.UploaderUserId != currentUserId && !isAdmin)
                {
                    return Json(new { success = false, message = "Bu dosyayı silme yetkiniz yok." });
                }

                // Admin ise dosya sahibi kontrolü - Normal admin diğer adminlerin dosyalarını silemez
                if (isAdmin && !string.IsNullOrEmpty(file.UploaderUserId))
                {
                    var fileOwner = await _userManager.FindByIdAsync(file.UploaderUserId);
                    if (fileOwner != null && await _userManager.IsInRoleAsync(fileOwner, "Admin") && !IsSuperAdmin())
                    {
                        return Json(new { success = false, message = "Diğer adminlerin dosyalarını silemezsiniz." });
                    }
                }

                // Fiziksel dosyayı sil - Güvenlik kontrolü
                if (!string.IsNullOrEmpty(file.FilePath))
                {
                    var relativePath = file.FilePath.TrimStart('/');
                    var filePath = Path.Combine(_webHostEnvironment.WebRootPath, relativePath);

                    // Path traversal saldırısına karşı güvenlik
                    var fullWebRootPath = Path.GetFullPath(_webHostEnvironment.WebRootPath);
                    var fullFilePath = Path.GetFullPath(filePath);

                    if (fullFilePath.StartsWith(fullWebRootPath, StringComparison.OrdinalIgnoreCase))
                    {
                        if (System.IO.File.Exists(fullFilePath))
                        {
                            try
                            {
                                System.IO.File.Delete(fullFilePath);
                            }
                            catch (Exception ex)
                            {
                                _logger.LogWarning(ex, "Dosya silme hatası: {FilePath}", fullFilePath);
                            }
                        }
                    }
                }

                // Veritabanından sil - Repository Pattern
                _fileRepository.Remove(file);
                await _fileRepository.SaveChangesAsync();

                // Log kaydı - Aktivite takibi
                var logUserId = User.FindFirstValue(ClaimTypes.NameIdentifier);
                var userEmail = User.Identity?.Name;
                var ipAddress = HttpContext.Connection.RemoteIpAddress?.ToString();
                await _logService.LogAsync(
                    logUserId ?? "",
                    userEmail,
                    "FileDeleted",
                    $"Dosya silindi: {file.FileName}",
                    file.FileName,
                    file.Id,
                    ipAddress
                );

                // AJAX için JSON response döndür
                return Json(new { success = true, message = "Dosya başarıyla silindi." });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Dosya silme hatası");
                return Json(new { success = false, message = "Dosya silinirken bir hata oluştu." });
            }
        }
    }
}
