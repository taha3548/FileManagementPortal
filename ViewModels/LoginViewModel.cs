using System.ComponentModel.DataAnnotations;

namespace FileManagementPortal.ViewModels
{
    public class LoginViewModel
    {
        [Required(ErrorMessage = "E-posta adresi gereklidir")]
        [EmailAddress(ErrorMessage = "Geçerli bir e-posta adresi girin")]
        [Display(Name = "E-posta")]
        public string Email { get; set; } = string.Empty;

        [Required(ErrorMessage = "Şifre gereklidir")]
        [DataType(DataType.Password)]
        [Display(Name = "Şifre")]
        public string Password { get; set; } = string.Empty;

        [DataType(DataType.Password)]
        [Display(Name = "Şifreyi Onayla")]
        public string? ConfirmPassword { get; set; }

        [Display(Name = "Beni Hatırla")]
        public bool RememberMe { get; set; } = true;

        public string? ReturnUrl { get; set; }
    }
}






