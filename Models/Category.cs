// Kategori bilgilerini tutan model sınıfı

using System.ComponentModel.DataAnnotations;

namespace FileManagementPortal.Models
{
    public class Category
    {
        [Key]
        public int Id { get; set; }

        [Required(ErrorMessage = "Kategori adı zorunludur")]
        [StringLength(100)]
        public string Name { get; set; } = string.Empty;

        [StringLength(500)]
        public string? Description { get; set; }

        public bool IsActive { get; set; } = true;

        public DateTime CreatedAt { get; set; } = DateTime.Now;

        // Çoka-çok ilişki: Kategoride birden fazla dosya olabilir
        public virtual ICollection<FileItem>? Files { get; set; }
    }
}
