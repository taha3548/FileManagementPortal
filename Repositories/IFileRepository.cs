// Dosya işlemleri için özel Repository Interface

using FileManagementPortal.Models;

namespace FileManagementPortal.Repositories
{
    public interface IFileRepository : IRepository<FileItem>
    {
        Task<IEnumerable<FileItem>> GetActiveFilesAsync();
        Task<IEnumerable<FileItem>> GetFilesByCategoryAsync(int categoryId);
        Task<IEnumerable<FileItem>> GetUserFilesAsync(string userId);
        Task<IEnumerable<FileItem>> GetMostDownloadedAsync(int count = 10);
        Task<IEnumerable<FileItem>> GetLatestAsync(int count = 10);
        Task<FileItem?> GetFileDetailAsync(int id);
        Task IncrementDownloadCountAsync(int fileId);
    }
}
