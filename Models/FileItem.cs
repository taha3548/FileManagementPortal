// Dosya bilgilerini tutan model sınıfı

using System.ComponentModel.DataAnnotations;

namespace FileManagementPortal.Models
{
    public class FileItem
    {
        [Key]
        public int Id { get; set; }

        [Required(ErrorMessage = "Dosya adı zorunludur")]
        [StringLength(255)]
        public string FileName { get; set; } = string.Empty;

        [StringLength(500)]
        public string? Description { get; set; }

        [Required]
        public long FileSize { get; set; }

        [Required]
        [StringLength(50)]
        public string FileType { get; set; } = string.Empty;

        [Required]
        public DateTime UploadedAt { get; set; } = DateTime.Now;

        [StringLength(450)]
        public string? UploaderUserId { get; set; }

        [StringLength(500)]
        public string? FilePath { get; set; }

        // Çoka-çok ilişki: Dosya birden fazla kategoriye ait olabilir
        public virtual ICollection<Category> Categories { get; set; } = new List<Category>();

        public bool IsActive { get; set; } = true;

        public int DownloadCount { get; set; } = 0;
    }
}
