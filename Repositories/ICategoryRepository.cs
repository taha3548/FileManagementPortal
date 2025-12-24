// Category Repository Interface - Kategori işlemleri için özel metodlar

using FileManagementPortal.Models;

namespace FileManagementPortal.Repositories
{
    public interface ICategoryRepository : IRepository<Category>
    {
        Task<IEnumerable<Category>> GetActiveCategoriesAsync();
        Task<Category?> GetCategoryDetailAsync(int id);
    }
}
