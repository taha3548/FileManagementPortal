// Log Service - Kullanıcı aktivitelerini veritabanına kaydeder

using FileManagementPortal.Migrations;
using FileManagementPortal.Models;

namespace FileManagementPortal.Services
{
    // Log servisi arayüzü
    public interface ILogService
    {
        Task LogAsync(string userId, string? userEmail, string activityType, string? description = null, 
            string? relatedFileName = null, int? relatedFileId = null, string? ipAddress = null, 
            bool success = true, string? errorMessage = null);
    }

    // Log servisi implementasyonu - UserLog tablosuna kayıt ekler
    public class LogService : ILogService
    {
        private readonly AppDbContext _context;

        public LogService(AppDbContext context)
        {
            _context = context;
        }

        // Kullanıcı aktivitesini logla
        public async Task LogAsync(string userId, string? userEmail, string activityType, string? description = null, 
            string? relatedFileName = null, int? relatedFileId = null, string? ipAddress = null, 
            bool success = true, string? errorMessage = null)
        {
            try
            {
                var log = new UserLog
                {
                    UserId = userId,
                    UserEmail = userEmail,
                    ActivityType = activityType,
                    Description = description,
                    RelatedFileName = relatedFileName,
                    RelatedFileId = relatedFileId,
                    IpAddress = ipAddress,
                    Date = DateTime.Now,
                    Success = success,
                    ErrorMessage = errorMessage
                };

                _context.UserLogs.Add(log);
                await _context.SaveChangesAsync();
            }
            catch (Exception)
            {
                // Log hatası ana işlemi etkilememeli
            }
        }
    }
}
