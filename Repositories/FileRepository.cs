// Dosya Repository - Entity Framework ile dosya veritabanı işlemleri

using FileManagementPortal.Migrations;
using FileManagementPortal.Models;
using Microsoft.EntityFrameworkCore;

namespace FileManagementPortal.Repositories
{
    public class FileRepository : Repository<FileItem>, IFileRepository
    {
        public FileRepository(AppDbContext context) : base(context)
        {
        }

        // Aktif dosyaları getir
        public async Task<IEnumerable<FileItem>> GetActiveFilesAsync()
        {
            return await _dbSet
                .Where(d => d.IsActive)
                .Include(d => d.Categories)
                .OrderByDescending(d => d.UploadedAt)
                .ToListAsync();
        }

        // Kategoriye göre dosyaları getir
        public async Task<IEnumerable<FileItem>> GetFilesByCategoryAsync(int categoryId)
        {
            return await _dbSet
                .Where(d => d.IsActive && d.Categories.Any(k => k.Id == categoryId))
                .Include(d => d.Categories)
                .OrderByDescending(d => d.UploadedAt)
                .ToListAsync();
        }

        // Kullanıcının dosyalarını getir
        public async Task<IEnumerable<FileItem>> GetUserFilesAsync(string userId)
        {
            return await _dbSet
                .Where(d => d.UploaderUserId == userId && d.IsActive)
                .Include(d => d.Categories)
                .OrderByDescending(d => d.UploadedAt)
                .ToListAsync();
        }

        // En çok indirilen dosyalar
        public async Task<IEnumerable<FileItem>> GetMostDownloadedAsync(int count = 10)
        {
            return await _dbSet
                .Where(d => d.IsActive)
                .Include(d => d.Categories)
                .OrderByDescending(d => d.DownloadCount)
                .Take(count)
                .ToListAsync();
        }

        // Son yüklenen dosyalar
        public async Task<IEnumerable<FileItem>> GetLatestAsync(int count = 10)
        {
            return await _dbSet
                .Where(d => d.IsActive)
                .Include(d => d.Categories)
                .OrderByDescending(d => d.UploadedAt)
                .Take(count)
                .ToListAsync();
        }

        // Dosya detayını getir (kategorilerle birlikte)
        public async Task<FileItem?> GetFileDetailAsync(int id)
        {
            return await _dbSet
                .Include(d => d.Categories)
                .FirstOrDefaultAsync(d => d.Id == id);
        }

        // İndirme sayısını artır
        public async Task IncrementDownloadCountAsync(int fileId)
        {
            var file = await _dbSet.FindAsync(fileId);
            if (file != null)
            {
                file.DownloadCount++;
                _dbSet.Update(file);
            }
        }
    }
}
