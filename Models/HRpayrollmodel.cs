using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using Microsoft.AspNetCore.Mvc.Rendering;
using Microsoft.EntityFrameworkCore;

namespace HRPayrollSystem.Models
{
    public class User
    {
        [Key]
        public int UserID { get; set; }
        public int EmployeeID { get; set; }
        [Required, StringLength(50)]
        public required string? Username { get; set; }
        [Required]
        public  string? PasswordHash { get; set; }
        [Required, StringLength(20)]
        public required string? Role { get; set; }
        public bool? TwoFactorEnabled { get; set; }
        public DateTime? LastLogin { get; set; }
        [Required, StringLength(10)]
        public required string? Status { get; set; } // Active, Inactive

        [ForeignKey("EmployeeID")]
        public virtual  Employee Employee { get; set; }
    }

    public class Employee
    {
        [Key]
        public int EmployeeID { get; set; }
        public int DepartmentID { get; set; }
        public int PositionID { get; set; }
        public int? SalaryGradeID { get; set; }
        [Required, StringLength(50)]
        public string? FirstName { get; set; }
        [Required, StringLength(50)]
        public string? LastName { get; set; }
        [Required, StringLength(10)]
        public string? Gender { get; set; }
        public DateTime? BirthDate { get; set; }
        [Required, StringLength(15)]
        public string? ContactNumber { get; set; }
        [Required, StringLength(50)]
        public string? Email { get; set; }
        [Required]
        public DateTime? HireDate { get; set; }
        [Required]
        public string? Address { get; set; }
        
        public string? PagIbigDoc { get; set; }
        
        public string? SSSDoc { get; set; }
       
        public string? PhilHealthDoc { get; set; }
       
        public string? BirthCertificateDoc { get; set; }
       
        public string? EmploymentStatus { get; set; } // Active, Inactive

        [ForeignKey("DepartmentID")]
        public virtual Department? Department { get; set; }
        [ForeignKey("PositionID")]
        public virtual Position? Position { get; set; }
        [ForeignKey("SalaryGradeID")]
        public virtual SalaryGrade? SalaryGrade { get; set; }

    }

    public class Department
    {
        [Key]
        public int DepartmentID { get; set; }

        [Required]
        [StringLength(100)]
        public string DepartmentName { get; set; }

        public int? ManagerID { get; set; }

        [ForeignKey("ManagerID")]
        public virtual Employee? Manager { get; set; }

        public virtual ICollection<Employee>? Employees { get; set; } = new List<Employee>();
    }

    public class Position
    {
        [Key]
        public int PositionID { get; set; }
        [Required, StringLength(50)]
        public required string? PositionTitle { get; set; }
        [Required]
        public required string? JobDescription { get; set; }
    }

    public class SalaryGrade
    {
        [Key]
        public int SalaryGradeID { get; set; }

        [Required, Precision(18, 2)]
        public decimal? BasicSalary { get; set; }

        [Required, Precision(18, 2)]
        public decimal? OvertimeRate { get; set; }

        [Required, Precision(18, 2)]
        public decimal? Allowances { get; set; }
    }

    public class Attendance
    {
        [Key]
        public int AttendanceID { get; set; }
        [ForeignKey("Employee")]
        public int? EmployeeID { get; set; }
        [Required]
        public DateTime? Date { get; set; }
        [Required]
        public TimeSpan? CheckInTime { get; set; }
        [Required]
        public TimeSpan? CheckOutTime { get; set; }
        [Required, Precision(18, 2)]
        public decimal? TotalHoursWorked { get; set; }

        [Required, Precision(18, 2)]
        public decimal? OvertimeHours { get; set; }
        [Required, StringLength(20)]
        public required string? AttendanceStatus { get; set; } // Present, Absent, Late
        [Required]
        public virtual Employee? Employee { get; set; }
        [NotMapped]
        public string? OvertimeHoursFormatted { get; set; }
    }

    public class Leave
    {
        [Key]
        public int LeaveID { get; set; }

        [ForeignKey("Employee")]
        public int EmployeeID { get; set; }

        [Required, MaxLength(20)]
        public string LeaveType { get; set; } = string.Empty;

        [Required]
        public DateTime StartDate { get; set; }

        [Required]
        public DateTime EndDate { get; set; }

        // Optional until set by backend logic
        public string? ApprovalStatus { get; set; }

        [ForeignKey("HR_Approver")]
        public int? HR_ApprovedBy { get; set; }

        [Required, MaxLength(500)]
        public string Reason { get; set; } = string.Empty;

        // Navigation Properties
        public virtual Employee? Employee { get; set; }
        public virtual Employee? HR_Approver { get; set; }
    }


    public class Payroll
    {
        [Key]
        public int PayrollID { get; set; }
        public int EmployeeID { get; set; }
        public int SalaryGradeID { get; set; }

        [Required]
        public DateTime? PayPeriod { get; set; }

        [Required, Precision(18, 2)]
        public decimal? GrossSalary { get; set; }

        [Required, Precision(18, 2)]
        public decimal? Deductions_SSS { get; set; }

        [Required, Precision(18, 2)]
        public decimal? Deductions_PhilHealth { get; set; }

        [Required, Precision(18, 2)]
        public decimal? Deductions_PagIbig { get; set; }

        [Required, Precision(18, 2)]
        public decimal? Absences {  get; set; }

        [Required, Precision(18, 2)]
        public decimal? TaxWithHolding { get; set; }

        [Required, Precision(18, 2)]
        public decimal NetSalary { get; set; }
        [Required, StringLength(20)]
        public required string? PayrollStatus { get; set; } // Processed, Pending
        [Required]
        public DateTime? DateProcessed { get; set; }

        [Required]
        public int? ProcessedBy { get; set; }

        [ForeignKey("EmployeeID")]
        public virtual  Employee? Employee { get; set; }
        [ForeignKey("SalaryGradeID")]
        public virtual  SalaryGrade? SalaryGrade { get; set; }
        [ForeignKey("ProcessedBy")]
        public virtual  User? ProcessedByUser { get; set; }
    }

    public class AuditLog
    {
        [Key]
        public int LogID { get; set; }
        public int UserID { get; set; }
        [Required]
        public required string? ActionTaken { get; set; }
        [Required]
        public DateTime? Timestamp { get; set; }
        [Required, StringLength(50)]
        public required string? IPAddress { get; set; }

        [ForeignKey(nameof(UserID))]
        public virtual User User { get; set; }
    }

    public class Office
    {
        public int OfficeID { get; set; }
        public string Name { get; set; }
        public string Address { get; set; }

        public string GeoFence { get; set; }
        public double Latitude { get; set; }
        public double Longitude { get; set; }
        public double RadiusInMeters { get; set; } // Radius for geofence
    }

    public class Announcements
    {
        public int AnnouncementID { get; set; }

        [Required]
        [MaxLength(150)]
        public string Title { get; set; }

        [Required]
        public string Message { get; set; }

        [Required]
        public string MessageType { get; set; }

        [Required]
        [MaxLength(100)]
        public string TargetType { get; set; }

        [Required]
        public int? CreatedBy { get; set; }

        public DateTime DatePosted { get; set; } = DateTime.Now;

        public DateTime? ExpiryDate { get; set; }

        public User CreatedByUser { get; set; }
    }


    public class CreateAnnouncementViewModel
    {
        [Required]
        public string Title { get; set; }

        [Required]
        public string Message { get; set; }

        [Required]
        public string MessageType { get; set; }

        [Required]
        [DataType(DataType.Date)]
        public DateTime ExpiryDate { get; set; }

        [Required]
        public string TargetType { get; set; } // Values: All, Department, Employee

        public int? DepartmentID { get; set; } // Optional, will be used when TargetType is Department
        public int? EmployeeID { get; set; } // Optional, will be used when TargetType is Employee

        public List<SelectListItem> Departments { get; set; } = new List<SelectListItem>();
        public List<SelectListItem> Employees { get; set; } = new List<SelectListItem>();
    }

    public class OfficeMapViewModel
    {
        public int OfficeID { get; set; }
        public string Name { get; set; }

        public string Address { get; set; }
        public double Latitude { get; set; }
        public double Longitude { get; set; }
        public string GeoFence { get; set; } // stored as raw string
    }








}