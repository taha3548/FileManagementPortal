// ============================================
// VERITABANI BAĞLAM SINIFI - AppDbContext
// ============================================
// Entity Framework Code-First yaklaşımı
// IdentityDbContext'ten türetilmiş
// SQL Server veritabanı bağlantısı
// ============================================

using FileManagementPortal.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace FileManagementPortal.Migrations
{
    // ASP.NET Identity tabloları otomatik oluşturulur:
    // AspNetUsers, AspNetRoles, AspNetUserRoles vb.
    public class AppDbContext : IdentityDbContext<AppUser, IdentityRole, string>
    {
        public AppDbContext(DbContextOptions<AppDbContext> options) : base(options)
        {
        }

        // Uygulama tabloları
        public DbSet<FileItem> Files => Set<FileItem>();
        public DbSet<Category> Categories => Set<Category>();
        public DbSet<UserLog> UserLogs => Set<UserLog>();

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            base.OnModelCreating(modelBuilder);

            // Dosya-Kategori çoka-çok ilişkisi (Many-to-Many)
            modelBuilder.Entity<FileItem>()
                .HasMany(d => d.Categories)
                .WithMany(k => k.Files)
                .UsingEntity<Dictionary<string, object>>(
                    "FileCategory",
                    j => j.HasOne<Category>().WithMany().HasForeignKey("CategoryId"),
                    j => j.HasOne<FileItem>().WithMany().HasForeignKey("FileId"),
                    j =>
                    {
                        j.HasKey("FileId", "CategoryId");
                        j.ToTable("FileCategory");
                    });
        }
    }
}
