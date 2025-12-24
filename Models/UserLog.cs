// Kullanıcı aktivite loglarını tutan model sınıfı

using System.ComponentModel.DataAnnotations;

namespace FileManagementPortal.Models
{
    public class UserLog
    {
        [Key]
        public int Id { get; set; }

        [Required]
        [StringLength(450)]
        public string UserId { get; set; } = string.Empty;

        [StringLength(255)]
        public string? UserEmail { get; set; }

        [Required]
        [StringLength(100)]
        public string ActivityType { get; set; } = string.Empty;

        [StringLength(500)]
        public string? Description { get; set; }

        [StringLength(255)]
        public string? RelatedFileName { get; set; }

        public int? RelatedFileId { get; set; }

        [StringLength(50)]
        public string? IpAddress { get; set; }

        [Required]
        public DateTime Date { get; set; } = DateTime.Now;

        public bool Success { get; set; } = true;

        [StringLength(500)]
        public string? ErrorMessage { get; set; }
    }
}
