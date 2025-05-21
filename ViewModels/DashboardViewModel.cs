using System;
using System.Collections.Generic;
using HRPayrollSystem.Models;

namespace HRPayrollSystem.ViewModels
{
    public class DashboardViewModel
    {
        public IEnumerable<Announcements> Announcements { get; set; }
        public TimeSpan? CheckInTime { get; set; }
        public TimeSpan? CheckOutTime { get; set; }
        
        // Time Log Properties
        public TimeSpan ScheduledHours { get; set; } = new TimeSpan(8, 0, 0); // Default 8 hours
        public TimeSpan? WorkedHours { get; set; }
        public TimeSpan? BalanceHours { get; set; }
        
        // Monthly Summary
        public decimal TotalHours { get; set; }
        public decimal ShortageHours { get; set; }
        public decimal OvertimeHours { get; set; }
        public decimal WorkedTimeHours { get; set; }

        // Leave Statistics
        public int TotalLeaveAllowance { get; set; }
        public int TotalLeaveTaken { get; set; }
        public int LeaveBalance { get; set; }
        public int PendingLeaveRequests { get; set; }

        // Payroll Information
        public decimal CurrentSalary { get; set; }
        public decimal LastPayrollAmount { get; set; }
        public DateTime? LastPayrollDate { get; set; }
        public int DaysUntilNextPayroll { get; set; }

        // Attendance Statistics
        public int PresentDaysThisMonth { get; set; }
        public int AbsentDaysThisMonth { get; set; }
        public int LateDaysThisMonth { get; set; }
        public decimal AttendanceRate { get; set; }
    }
} 