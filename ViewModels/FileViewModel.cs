using System.ComponentModel.DataAnnotations;
using FileManagementPortal.Models;

namespace FileManagementPortal.ViewModels
{
    // View model used for creating and editing files
    // Used by FileController.Create (GET/POST) and AdminController.FileEdit actions
    public class FileViewModel
    {
        // File ID (used for edits)
        public int Id { get; set; }

        // Display name of the file (entered by user)
        [Required(ErrorMessage = "Dosya adı gereklidir")]
        [StringLength(255)]
        [Display(Name = "Dosya Adı")]
        public string FileName { get; set; } = string.Empty;

        // Optional description for the file
        [StringLength(500)]
        [Display(Name = "Açıklama")]
        public string? Description { get; set; }

        // Selected category IDs (multiple selection)
        [Required(ErrorMessage = "En az bir kategori seçmelisiniz")]
        [MinLength(1, ErrorMessage = "En az bir kategori seçmelisiniz")]
        [Display(Name = "Kategoriler")]
        public List<int> CategoryIds { get; set; } = new List<int>();

        // The uploaded file (IFormFile)
        [Required(ErrorMessage = "Lütfen yüklenecek bir dosya seçin")]
        [Display(Name = "Dosya")]
        public IFormFile? File { get; set; }

        // All active categories for display in the form
        public List<Category>? Categories { get; set; }
    }

    // View model for file list (File/Index)
    public class FileListViewModel
    {
        // Files to display
        public IEnumerable<FileItem> Files { get; set; } = new List<FileItem>();

        // Active categories for the filter dropdown
        public IEnumerable<Category> Categories { get; set; } = new List<Category>();

        // Selected category id for filtering
        public int? SelectedCategoryId { get; set; }

        // Search term for filtering
        public string? SearchTerm { get; set; }
    }

    // View model for file details (File/Details)
    public class FileDetailViewModel
    {
        // The file to show details for
        public FileItem File { get; set; } = null!;

        // Similar files to suggest
        public IEnumerable<FileItem> SimilarFiles { get; set; } = new List<FileItem>();
    }

    // View model for editing file name and description
    public class FileEditViewModel
    {
        public int Id { get; set; }

        [Required(ErrorMessage = "Dosya adı gereklidir")]
        [StringLength(255)]
        [Display(Name = "Dosya Adı")]
        public string FileName { get; set; } = string.Empty;

        [StringLength(500)]
        [Display(Name = "Açıklama")]
        public string? Description { get; set; }
    }
}
