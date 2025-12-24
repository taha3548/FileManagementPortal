using FileManagementPortal.Models;
using System.ComponentModel.DataAnnotations;

namespace FileManagementPortal.ViewModels
{
    public class AdminDashboardViewModel
    {
        public int TotalFileCount { get; set; }
        public int TotalCategoryCount { get; set; }
        public int TotalUserCount { get; set; }
        public int TotalAdminCount { get; set; }
        public long TotalFileSize { get; set; }
        public IEnumerable<FileItem> RecentlyUploadedFiles { get; set; } = new List<FileItem>();
        public IEnumerable<FileItem> MostDownloadedFiles { get; set; } = new List<FileItem>();
    }

    public class CategoryViewModel
    {
        public int Id { get; set; }

        [Required(ErrorMessage = "Kategori adı gereklidir")]
        [StringLength(100)]
        [Display(Name = "Kategori Adı")]
        public string Name { get; set; } = string.Empty;

        [StringLength(500)]
        [Display(Name = "Açıklama")]
        public string? Description { get; set; }

        [Display(Name = "Aktif")]
        public bool IsActive { get; set; } = true;
    }

    public class UserViewModel
    {
        public string Id { get; set; } = string.Empty;
        public string Email { get; set; } = string.Empty;
        public string? UserName { get; set; }
        public List<string> Roles { get; set; } = new List<string>();
        public bool EmailConfirmed { get; set; }
        public int FileCount { get; set; }
    }

    public class UserDetailViewModel
    {
        public string Id { get; set; } = string.Empty;
        public string Email { get; set; } = string.Empty;
        public string? UserName { get; set; }
        public List<string> Roles { get; set; } = new List<string>();
        public bool EmailConfirmed { get; set; }
        public int TotalFileCount { get; set; }
        public long TotalFileSize { get; set; }
        public List<FileItem> Files { get; set; } = new List<FileItem>();
        public List<UserLog> Logs { get; set; } = new List<UserLog>();
        public string? PlainPassword { get; set; }
        public bool CanViewPassword { get; set; }
    }

    public class UserChangePasswordViewModel
    {
        public string UserId { get; set; } = string.Empty;
        public string Email { get; set; } = string.Empty;

        [Required(ErrorMessage = "Yeni şifre gereklidir")]
        [StringLength(100, MinimumLength = 6, ErrorMessage = "Şifre en az 6 karakter olmalıdır")]
        [DataType(DataType.Password)]
        [Display(Name = "Yeni Şifre")]
        public string NewPassword { get; set; } = string.Empty;

        [Required(ErrorMessage = "Şifre onayı gereklidir")]
        [DataType(DataType.Password)]
        [Display(Name = "Şifreyi Onayla")]
        [Compare("NewPassword", ErrorMessage = "Şifreler eşleşmiyor")]
        public string ConfirmPassword { get; set; } = string.Empty;
    }

    public class UserRoleViewModel
    {
        public string UserId { get; set; } = string.Empty;
        public string Email { get; set; } = string.Empty;
        public List<string> CurrentRoles { get; set; } = new List<string>();
        public List<string> AllRoles { get; set; } = new List<string>();
    }
}
