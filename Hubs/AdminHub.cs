// ============================================
// SIGNALR HUB - Admin Paneli Bildirimleri
// ============================================
// Gerçek zamanlı bildirimler (Real-time)
// WebSocket ile çift yönlü iletişim
// Dosya yükleme/indirme/silme bildirimleri
// ============================================

using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.SignalR;

namespace FileManagementPortal.Hubs
{
    [Authorize(Roles = "Admin")]
    public class AdminHub : Hub
    {
        // Bağlı admin sayısı
        private static HashSet<string> _connectedAdmins = new HashSet<string>();

        // Admin bağlandığında
        public override async Task OnConnectedAsync()
        {
            var adminId = Context.User?.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value;
            if (!string.IsNullOrEmpty(adminId))
            {
                _connectedAdmins.Add(Context.ConnectionId);
                await Clients.All.SendAsync("AdminConnected", adminId, _connectedAdmins.Count);
            }
            await base.OnConnectedAsync();
        }

        // Admin ayrıldığında
        public override async Task OnDisconnectedAsync(Exception? exception)
        {
            _connectedAdmins.Remove(Context.ConnectionId);
            await Clients.All.SendAsync("AdminDisconnected", _connectedAdmins.Count);
            await base.OnDisconnectedAsync(exception);
        }

        // Dosya yükleme bildirimi
        public async Task NotifyFileUploaded(string fileName, string uploaderEmail)
        {
            await Clients.All.SendAsync("FileUploaded", new
            {
                FileName = fileName,
                UploaderEmail = uploaderEmail,
                Timestamp = DateTime.Now.ToString("dd.MM.yyyy HH:mm:ss")
            });
        }

        // Dosya indirme bildirimi
        public async Task NotifyFileDownloaded(string fileName, string downloaderEmail)
        {
            await Clients.All.SendAsync("FileDownloaded", new
            {
                FileName = fileName,
                DownloaderEmail = downloaderEmail,
                Timestamp = DateTime.Now.ToString("dd.MM.yyyy HH:mm:ss")
            });
        }

        // Dosya silme bildirimi
        public async Task NotifyFileDeleted(string fileName, string deleterEmail)
        {
            await Clients.All.SendAsync("FileDeleted", new
            {
                FileName = fileName,
                DeleterEmail = deleterEmail,
                Timestamp = DateTime.Now.ToString("dd.MM.yyyy HH:mm:ss")
            });
        }

        // Yeni kullanıcı kayıt bildirimi
        public async Task NotifyUserRegistered(string userEmail)
        {
            await Clients.All.SendAsync("UserRegistered", new
            {
                UserEmail = userEmail,
                Timestamp = DateTime.Now.ToString("dd.MM.yyyy HH:mm:ss")
            });
        }

        // Bağlı admin sayısını sorgula
        public async Task GetConnectedAdminsCount()
        {
            await Clients.Caller.SendAsync("ConnectedAdminsCount", _connectedAdmins.Count);
        }
    }
}
