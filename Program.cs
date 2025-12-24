// ============================================================================
// DOSYA YONETIM PORTALI - ANA PROGRAM DOSYASI (Program.cs)
// ============================================================================
// Bu dosya ASP.NET Core uygulamasinin baslangic noktasidir.
// ASP.NET IDENTITY uyelik sistemi burada yapilandirilmistir.
// ============================================================================

using System.Globalization;
using FileManagementPortal.Migrations;
using FileManagementPortal.Models;
using FileManagementPortal.Repositories;
using FileManagementPortal.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

// UYGULAMA BASLATMA
var builder = WebApplication.CreateBuilder(args);

// ============================================================================
// ENTITY FRAMEWORK CORE - VERITABANI BAGLANTISI
// ============================================================================
var connectionString = builder.Configuration.GetConnectionString("DefaultConnection") 
    ?? throw new InvalidOperationException("Connection string 'DefaultConnection' not found.");

builder.Services.AddDbContext<AppDbContext>(options =>
    options.UseSqlServer(connectionString));

builder.Services.AddDatabaseDeveloperPageExceptionFilter();

// ============================================================================
// ASP.NET IDENTITY - UYELIK SISTEMI YAPILANDIRMASI
// ============================================================================
builder.Services.AddIdentity<AppUser, IdentityRole>(options =>
{
    // SIFRE KURALLARI
    options.Password.RequireDigit = false;
    options.Password.RequireLowercase = false;
    options.Password.RequireUppercase = false;
    options.Password.RequireNonAlphanumeric = false;
    options.Password.RequiredLength = 6;

    // KULLANICI AYARLARI
    options.User.RequireUniqueEmail = true;
    options.User.AllowedUserNameCharacters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._@+";

    // OTURUM AYARLARI
    options.SignIn.RequireConfirmedEmail = false;
    options.SignIn.RequireConfirmedAccount = false;
})
.AddEntityFrameworkStores<AppDbContext>()
.AddDefaultTokenProviders();

// ============================================================================
// COOKIE AUTHENTICATION - CEREZ AYARLARI
// ============================================================================
builder.Services.ConfigureApplicationCookie(options =>
{
    options.LoginPath = "/Account/Login";
    options.LogoutPath = "/Account/Logout";
    options.AccessDeniedPath = "/Account/AccessDenied";
    options.ExpireTimeSpan = TimeSpan.FromDays(7);
    options.SlidingExpiration = true;
    options.Cookie.HttpOnly = true;
    options.Cookie.SecurePolicy = CookieSecurePolicy.SameAsRequest;
});

// AUTHORIZATION
builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("AdminOnly", policy => policy.RequireRole("Admin"));
});

// LOCALIZATION AYARLARI
builder.Services.AddLocalization(options => options.ResourcesPath = "Resources");

var supportedCultures = new[]
{
    new CultureInfo("en-US"),
    new CultureInfo("tr-TR")
};

builder.Services.Configure<RequestLocalizationOptions>(options =>
{
    options.DefaultRequestCulture = new Microsoft.AspNetCore.Localization.RequestCulture("en-US");
    options.SupportedCultures = supportedCultures;
    options.SupportedUICultures = supportedCultures;
});

// ============================================================================
// DEPENDENCY INJECTION - SERVIS KAYITLARI
// ============================================================================
builder.Services.AddScoped<ICustomUserService, CustomUserService>();
builder.Services.AddSingleton<IHttpContextAccessor, HttpContextAccessor>();
builder.Services.AddRazorPages();

// ============================================================================
// SIGNALR - GERCEK ZAMANLI ILETISIM
// ============================================================================
builder.Services.AddSignalR();

// ============================================================================
// REPOSITORY PATTERN - VERI ERISIM KATMANI
// ============================================================================
builder.Services.AddScoped<IFileRepository, FileRepository>();
builder.Services.AddScoped<ICategoryRepository, CategoryRepository>();
builder.Services.AddScoped<FileManagementPortal.Services.ILogService, FileManagementPortal.Services.LogService>();

builder.Services.AddControllersWithViews();

var app = builder.Build();

// ============================================================================
// ENTITY FRAMEWORK - OTOMATIK VERITABANI OLUSTURMA
// ============================================================================
using (var scope = app.Services.CreateScope())
{
    var dbContext = scope.ServiceProvider.GetRequiredService<AppDbContext>();
    dbContext.Database.EnsureCreated();
}

// MIDDLEWARE PIPELINE
app.UseRequestLocalization();

if (app.Environment.IsDevelopment())
{
    app.UseDeveloperExceptionPage();
}
else
{
    app.UseExceptionHandler("/Home/Error");
}

app.UseStaticFiles();
app.UseRouting();

// ============================================================================
// ASP.NET IDENTITY - AUTHENTICATION & AUTHORIZATION MIDDLEWARE
// ============================================================================
app.UseAuthentication();
app.UseAuthorization();

// ROUTE YAPILANDIRMASI
app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");
app.MapRazorPages();

// ============================================================================
// SIGNALR HUB ENDPOINT
// ============================================================================
app.MapHub<FileManagementPortal.Hubs.AdminHub>("/hubs/admin");

// ============================================================================
// VARSAYILAN VERILERIN OLUSTURULMASI (SEED DATA)
// ============================================================================
using (var scope = app.Services.CreateScope())
{
    var services = scope.ServiceProvider;
    
    try
    {
        var userManager = services.GetRequiredService<UserManager<AppUser>>();
        var roleManager = services.GetRequiredService<RoleManager<IdentityRole>>();
        var categoryRepository = services.GetRequiredService<ICategoryRepository>();
        var logger = services.GetRequiredService<ILogger<Program>>();

        // ROL OLUSTURMA
        string[] roles = { "User", "Admin" };
        foreach (var role in roles)
        {
            if (!await roleManager.RoleExistsAsync(role))
            {
                await roleManager.CreateAsync(new IdentityRole(role));
                logger.LogInformation("Role created: {Role}", role);
            }
        }

        // ADMIN KULLANICI OLUSTURMA
        var adminEmail = "admin@gmail.com";
        var adminPassword = "Taha123";

        var adminUser = await userManager.FindByEmailAsync(adminEmail);

        if (adminUser == null)
        {
            adminUser = new AppUser
            {
                UserName = adminEmail,
                Email = adminEmail,
                EmailConfirmed = true,
                PlainPassword = adminPassword,
                CreatedAt = DateTime.UtcNow
            };

            var result = await userManager.CreateAsync(adminUser, adminPassword);
            
            if (result.Succeeded)
            {
                await userManager.AddToRoleAsync(adminUser, "Admin");
                await userManager.AddToRoleAsync(adminUser, "User");
                logger.LogInformation("Admin user created: {Email}", adminEmail);
            }
            else
            {
                logger.LogError("Failed to create admin user: {Errors}", 
                    string.Join(", ", result.Errors.Select(e => e.Description)));
            }
        }
        else
        {
            var token = await userManager.GeneratePasswordResetTokenAsync(adminUser);
            await userManager.ResetPasswordAsync(adminUser, token, adminPassword);
            adminUser.PlainPassword = adminPassword;
            await userManager.UpdateAsync(adminUser);
            
            if (!await userManager.IsInRoleAsync(adminUser, "Admin"))
            {
                await userManager.AddToRoleAsync(adminUser, "Admin");
            }
            if (!await userManager.IsInRoleAsync(adminUser, "User"))
            {
                await userManager.AddToRoleAsync(adminUser, "User");
            }
        }

        // VARSAYILAN KATEGORILER
        var defaultCategories = new[]
        {
            new Category { Name = "Dokuman", Description = "Word, PDF, Excel, PowerPoint", IsActive = true, CreatedAt = DateTime.Now },
            new Category { Name = "Video", Description = "Video dosyalari", IsActive = true, CreatedAt = DateTime.Now },
            new Category { Name = "Gorsel", Description = "Fotograf ve gorseller", IsActive = true, CreatedAt = DateTime.Now },
            new Category { Name = "Ses", Description = "Ses ve muzik dosyalari", IsActive = true, CreatedAt = DateTime.Now },
            new Category { Name = "Tasarim", Description = "Tasarim dosyalari", IsActive = true, CreatedAt = DateTime.Now },
            new Category { Name = "Arsiv", Description = "ZIP, RAR vb.", IsActive = true, CreatedAt = DateTime.Now },
            new Category { Name = "Yazilim", Description = "Program ve uygulama dosyalari", IsActive = true, CreatedAt = DateTime.Now },
            new Category { Name = "Diger", Description = "Diger dosya turleri", IsActive = true, CreatedAt = DateTime.Now }
        };

        var dbContext = services.GetRequiredService<AppDbContext>();
        var existingCategories = await categoryRepository.GetAllAsync();
        var defaultCategoryNames = defaultCategories.Select(c => c.Name).ToList();
        
        var categoriesToDelete = existingCategories.Where(c => !defaultCategoryNames.Contains(c.Name)).ToList();
        
        foreach (var categoryToDelete in categoriesToDelete)
        {
            var files = await dbContext.Files
                .Include(f => f.Categories)
                .Where(f => f.Categories.Any(c => c.Id == categoryToDelete.Id))
                .ToListAsync();
            
            foreach (var file in files)
            {
                file.Categories.Remove(categoryToDelete);
            }
            
            categoryRepository.Remove(categoryToDelete);
        }
        
        foreach (var category in defaultCategories)
        {
            var existingCategory = existingCategories.FirstOrDefault(c => c.Name == category.Name);
            
            if (existingCategory == null)
            {
                await categoryRepository.AddAsync(category);
            }
            else
            {
                existingCategory.Description = category.Description;
                existingCategory.IsActive = true;
                categoryRepository.Update(existingCategory);
            }
        }
        
        await categoryRepository.SaveChangesAsync();
    }
    catch (Exception ex)
    {
        var logger = services.GetRequiredService<ILogger<Program>>();
        logger.LogError(ex, "An error occurred while seeding the database.");
    }
}

app.Run();
