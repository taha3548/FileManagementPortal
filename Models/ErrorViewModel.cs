namespace FileManagementPortal.Models
{
    // Hata sayfasında (Home/Error) gösterilecek hata bilgilerini taşıyan view model
    // HomeController.Error action'ında oluşturulup view'a gönderiliyor
    // ASP.NET Core'un varsayılan hata yönetimi için kullanılıyor
    public class ErrorViewModel
    {
        // Hata oluşan request'in unique ID'si
        // HomeController.Error action'ında Activity.Current?.Id ?? HttpContext.TraceIdentifier ile set ediliyor
        // Hata loglarında bu ID ile hata takibi yapılabilir
        // Nullable olduğu için her zaman dolu olmayabilir
        public string? RequestId { get; set; }

        // RequestId'nin gösterilip gösterilmeyeceğini belirleyen property
        // RequestId null veya boş değilse true döner
        // View'da bu property'ye göre RequestId gösterilir veya gizlenir
        // Expression-bodied property: tek satırda getter tanımı
        public bool ShowRequestId => !string.IsNullOrEmpty(RequestId);
    }
}
