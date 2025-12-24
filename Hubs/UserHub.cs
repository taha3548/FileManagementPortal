// UserHub - Tüm kullanıcılar için SignalR Hub
// Çevrimiçi kullanıcı takibi - Anasayfada gösterilir

using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.SignalR;

namespace FileManagementPortal.Hubs
{
    [Authorize] // Sadece giriş yapmış kullanıcılar
    public class UserHub : Hub
    {
        // Çevrimiçi kullanıcılar (ConnectionId -> UserId)
        private static Dictionary<string, string> _onlineUsers = new Dictionary<string, string>();

        // Kullanıcı bağlandığında - SignalR otomatik çağırır
        public override async Task OnConnectedAsync()
        {
            var userId = Context.User?.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value;
            if (!string.IsNullOrEmpty(userId))
            {
                _onlineUsers[Context.ConnectionId] = userId;
                // Tüm kullanıcılara bildir
                await Clients.All.SendAsync("UserConnected", userId, GetOnlineUserIds());
            }
            await base.OnConnectedAsync();
        }

        // Kullanıcı ayrıldığında - SignalR otomatik çağırır
        public override async Task OnDisconnectedAsync(Exception? exception)
        {
            if (_onlineUsers.ContainsKey(Context.ConnectionId))
            {
                var userId = _onlineUsers[Context.ConnectionId];
                _onlineUsers.Remove(Context.ConnectionId);
                // Tüm kullanıcılara bildir
                await Clients.All.SendAsync("UserDisconnected", userId, GetOnlineUserIds());
            }
            await base.OnDisconnectedAsync(exception);
        }

        // Çevrimiçi kullanıcı ID'lerini getir
        public static List<string> GetOnlineUserIds()
        {
            return _onlineUsers.Values.Distinct().ToList();
        }

        // Çevrimiçi kullanıcı sayısını getir - Client'tan çağrılır
        public async Task GetOnlineUsers()
        {
            await Clients.Caller.SendAsync("OnlineUsers", GetOnlineUserIds());
        }
    }
}
