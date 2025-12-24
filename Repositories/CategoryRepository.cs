// Category Repository - Kategori veritabanı işlemleri

using FileManagementPortal.Migrations;
using FileManagementPortal.Models;
using Microsoft.EntityFrameworkCore;

namespace FileManagementPortal.Repositories
{
    public class CategoryRepository : Repository<Category>, ICategoryRepository
    {
        public CategoryRepository(AppDbContext context) : base(context)
        {
        }

        // Aktif kategorileri getir
        public async Task<IEnumerable<Category>> GetActiveCategoriesAsync()
        {
            return await _dbSet
                .Where(k => k.IsActive)
                .OrderBy(k => k.Name)
                .ToListAsync();
        }

        // Kategori detayını getir (dosyalarla birlikte)
        public async Task<Category?> GetCategoryDetailAsync(int id)
        {
            return await _dbSet
                .Include(k => k.Files)
                .FirstOrDefaultAsync(k => k.Id == id);
        }
    }
}
