// YourDbContext.cs
using Microsoft.EntityFrameworkCore;

public class LoginDbContext : DbContext
{
    public LoginDbContext(DbContextOptions<LoginDbContext> options) : base(options)
    {
    }

    public DbSet<EmpCreds> EmpCreds { get; set; }
}