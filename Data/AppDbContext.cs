using HRPayrollSystem.Models;
using Microsoft.EntityFrameworkCore;

public class AppDbContext : DbContext
{
    public AppDbContext(DbContextOptions<AppDbContext> options) : base(options) { }

    public DbSet<Employee> Employees { get; set; }
    public DbSet<Department>? Departments { get; set; }
    public DbSet<Position>? Positions { get; set; }
    public DbSet<SalaryGrade>? SalaryGrades { get; set; }
    public DbSet<Attendance>? Attendances { get; set; }
    public DbSet<Leave>? Leaves { get; set; }
    public DbSet<Payroll>? Payrolls { get; set; }
    public DbSet<User>? UserRoles { get; set; }
    public DbSet<AuditLog>? AuditLogs { get; set; }

    public DbSet<Office> Office { get; set; }

    public DbSet<Announcements> Announcements { get; set; }
 

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);

        // Employee Relations
        modelBuilder.Entity<Employee>()
            .HasOne(e => e.Department)
            .WithMany(d => d.Employees)
            .HasForeignKey(e => e.DepartmentID)
            .OnDelete(DeleteBehavior.Restrict);

        modelBuilder.Entity<Employee>()
            .HasOne(e => e.Position)
            .WithMany()
            .HasForeignKey(e => e.PositionID)
            .OnDelete(DeleteBehavior.Restrict);

        modelBuilder.Entity<Employee>()
            .HasOne(e => e.SalaryGrade)
            .WithMany()
            .HasForeignKey(e => e.SalaryGradeID)
            .OnDelete(DeleteBehavior.Restrict);

        // Payroll Relations
        modelBuilder.Entity<Payroll>()
            .HasOne(p => p.Employee)
            .WithMany()
            .HasForeignKey(p => p.EmployeeID)
            .OnDelete(DeleteBehavior.Cascade);

        modelBuilder.Entity<Payroll>()
            .HasOne(p => p.SalaryGrade)
            .WithMany()
            .HasForeignKey(p => p.SalaryGradeID)
            .OnDelete(DeleteBehavior.Restrict);

        // Attendance Relations
        modelBuilder.Entity<Attendance>()
            .HasOne(a => a.Employee)
            .WithMany()
            .HasForeignKey(a => a.EmployeeID)
            .OnDelete(DeleteBehavior.Cascade);

        // Leave Relations
        modelBuilder.Entity<Leave>()
            .HasOne(l => l.Employee)
            .WithMany()
            .HasForeignKey(l => l.EmployeeID)
            .OnDelete(DeleteBehavior.Cascade);

        modelBuilder.Entity<Leave>()
            .HasOne(l => l.HR_Approver)
            .WithMany()
            .HasForeignKey(l => l.HR_ApprovedBy)
            .OnDelete(DeleteBehavior.Restrict);

        // Department Relations
        modelBuilder.Entity<Department>()
            .HasOne(d => d.Manager)
            .WithMany()
            .HasForeignKey(d => d.ManagerID)
            .OnDelete(DeleteBehavior.Restrict);

        modelBuilder.Entity<Announcements>()
    .HasKey(a => a.AnnouncementID);

        modelBuilder.Entity<Announcements>()
            .HasOne(a => a.CreatedByUser)
            .WithMany()
            .HasForeignKey(a => a.CreatedBy)
            .OnDelete(DeleteBehavior.Restrict);



    }
}
