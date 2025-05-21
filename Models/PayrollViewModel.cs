using System;
using System.ComponentModel.DataAnnotations;
using HRPayrollSystem.Models;

namespace HRPayrollSystem.ViewModels
{
    public class PayrollViewModel
    {
        public int PayrollId { get; set; }
        public int? EmployeeID { get; set; }
      
        public int? SalaryGradeID { get; set; }

        [Required]
        public DateTime? PayPeriod { get; set; }


        public string? EmployeeName { get; set; }
        public decimal? BasicSalary { get; set; }
        public decimal? OvertimeHours { get; set; }

        public decimal? OvertimeRate { get; set; }
        public decimal? OvertimePay { get; set; }
        public decimal? Allowances { get; set; }

        public decimal? Deductions_SSS { get; set; }
        public decimal? Deductions_PhilHealth { get; set; }
        public decimal? Deductions_PagIbig { get; set; }
        public decimal? AbsenceDeduction { get; set; }

        public decimal? WithholdingTax { get; set; }   

        public decimal? TotalDeductions { get; set; }

        public decimal? GrossSalary { get; set; }
        public decimal? NetSalary { get; set; }

        public string? PayrollStatus { get; set; }

        public List<Employee>? Employees { get; set; }

        // This is for the select list of Salary Grades
        public List<SalaryGrade>? SalaryGrades { get; set; }

        // ProcessedByUser can also be part of the ViewModel, if necessary
        public User? ProcessedByUser { get; set; }
    }
}
