using System.Diagnostics;
using System.Security.Claims;
using HRPayrollSystem.Models;
using HRPayrollSystem.ViewModels;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Authorization;
using static System.Runtime.InteropServices.JavaScript.JSType;
using Microsoft.VisualStudio.Web.CodeGenerators.Mvc.Templates.BlazorIdentity.Pages.Manage;
using System.Threading.Tasks;
using System.Text;
using System.Globalization;
using System.Security.Cryptography;
using HRPayrollSystem.Services;
using Microsoft.AspNetCore.Mvc.Rendering;
using System.Text.Json;
using NetTopologySuite.Geometries;
using NetTopologySuite.IO;
using System.Net.Http.Headers;



using Vonage.Users;
using System.Linq;
using System.Drawing.Printing;
using Microsoft.AspNetCore.Hosting;
using iTextSharp.text;
using iTextSharp.text.pdf;
using System.IO;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.DependencyInjection;
using System;
using System.Threading;
using Microsoft.Extensions.Configuration;

namespace HRPayrollSystem.Controllers
{
    public class HomeController : Controller
    {


        public IActionResult Index()
        {
            return View();
        }

        public IActionResult Privacy()
        {
            return View();
        }

        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }
    }

    public class AuthController : Controller
    {
        private readonly AppDbContext _context;
        private readonly IConfiguration _configuration;
        private static Dictionary<string, int> FailedLoginAttempts = new();
        private static Dictionary<string, DateTime> LockedOutUntil = new();
        private const int MaxFailedAttempts = 3;
        private static readonly TimeSpan LockoutDuration = TimeSpan.FromMinutes(3);

        public AuthController(AppDbContext context, IConfiguration configuration)
        {
            _context = context;
            _configuration = configuration;
        }

        public IActionResult Login() => View();

        [HttpPost]
        public async Task<IActionResult> Login(string username, string password, [FromServices] IVonageService vonage)
        {
            // Check if the account is currently locked
            if (LockedOutUntil.ContainsKey(username) && LockedOutUntil[username] > DateTime.UtcNow)
            {
                var remaining = LockedOutUntil[username] - DateTime.UtcNow;
                ViewBag.Error = $"Account is temporarily locked. Try again in {remaining.Minutes}m {remaining.Seconds}s.";
                return View();
            }

            // Get the reCAPTCHA response from the form
            string recaptchaResponse = Request.Form["g-recaptcha-response"];
            string secretKey = _configuration["Recaptcha:SecretKey"];

            // Verify reCAPTCHA with Google
            using var client = new HttpClient();
            var values = new Dictionary<string, string>
    {
        { "secret", secretKey },
        { "response", recaptchaResponse }
    };
            var content = new FormUrlEncodedContent(values);
            var response = await client.PostAsync("https://www.google.com/recaptcha/api/siteverify", content);
            var responseString = await response.Content.ReadAsStringAsync();

            var captchaResult = JsonSerializer.Deserialize<RecaptchaResponse>(responseString);

            // If reCAPTCHA fails, return with an error
            if (captchaResult == null || !captchaResult.success)
            {
                ViewBag.Error = "reCAPTCHA verification failed. Please try again.";
                return View();
            }

            // Proceed with normal login process
            var user = _context.UserRoles?.FirstOrDefault(u => u.Username == username);


            // If user not found or password invalid
            if (user == null || !VerifyPassword(password, user.PasswordHash))
            {
                // Increment failed attempts
                if (!FailedLoginAttempts.ContainsKey(username))
                    FailedLoginAttempts[username] = 1;
                else
                    FailedLoginAttempts[username]++;

                // Lock the account if too many failed attempts
                if (FailedLoginAttempts[username] >= MaxFailedAttempts)
                {
                    LockedOutUntil[username] = DateTime.UtcNow.Add(LockoutDuration);
                    FailedLoginAttempts.Remove(username); // reset counter after locking
                    ViewBag.Error = "Too many failed attempts. Account locked for 3 minutes.";
                    return View();
                }

                ViewBag.Error = "Invalid username or password.";
                return View();
            }

            // Reset failed login state on success
            FailedLoginAttempts.Remove(username);
            LockedOutUntil.Remove(username);

            // Verify password hash
            if (!VerifyPassword(password, user.PasswordHash))
            {
                ViewBag.Error = "Invalid username or password.";
                return View();
            }

            var phoneNumber = _context.Employees
                .Where(e => e.EmployeeID == user.EmployeeID)
                .Select(e => e.ContactNumber)
                .FirstOrDefault();

            if (user.TwoFactorEnabled ?? false)
            {
                var requestId = await vonage.SendVerificationAsync(phoneNumber);

                TempData["RequestId"] = requestId;
                TempData["Username"] = username;
                TempData["Password"] = password;

                return RedirectToAction("Verify2FA");
            }
            else
            {
                // Bypass 2FA, proceed with login
                var claims = new List<Claim>
        {
            new Claim(ClaimTypes.Name, user.Username),
            new Claim(ClaimTypes.NameIdentifier, user.EmployeeID.ToString()),
            new Claim(ClaimTypes.Role, user.Role),
            new Claim("UserID", user.UserID.ToString())
        };

                var identity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
                var principal = new ClaimsPrincipal(identity);

                await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, principal);

                HttpContext.Session.SetInt32("EmployeeID", user.EmployeeID);
                HttpContext.Session.SetInt32("UserID", user.UserID);
                HttpContext.Session.SetString("Username", user.Username);
                HttpContext.Session.SetString("Role", user.Role);

                return RedirectToAction("Index", "Dashboard");
            }
        }

        // Helper method to verify password hash
        private bool VerifyPassword(string password, string storedHash)
        {
            byte[] storedHashBytes = Convert.FromBase64String(storedHash);

            // Extract the salt from the stored hash (first 16 bytes)
            byte[] salt = new byte[16];
            Buffer.BlockCopy(storedHashBytes, 0, salt, 0, 16);

            // Hash the provided password with the same salt
            var hash = new Rfc2898DeriveBytes(password, salt, 10000, HashAlgorithmName.SHA256);
            byte[] hashBytes = hash.GetBytes(32);

            // Compare the computed hash with the stored hash
            for (int i = 0; i < 32; i++)
            {
                if (hashBytes[i] != storedHashBytes[i + 16])
                {
                    return false;
                }
            }

            return true;
        }

        private string HashPassword(string password)
        {
            byte[] salt = RandomNumberGenerator.GetBytes(16);
            var hash = new Rfc2898DeriveBytes(password, salt, 10000, HashAlgorithmName.SHA256);
            byte[] hashBytes = hash.GetBytes(32);

            byte[] hashWithSalt = new byte[48];
            Buffer.BlockCopy(salt, 0, hashWithSalt, 0, 16);
            Buffer.BlockCopy(hashBytes, 0, hashWithSalt, 16, 32);

            return Convert.ToBase64String(hashWithSalt);
        }


        public class RecaptchaResponse
        {
            public bool success { get; set; }
            public float score { get; set; }
            public string action { get; set; }
            public DateTime challenge_ts { get; set; }
            public string hostname { get; set; }
            public List<string> errorCodes { get; set; }
        }



        public IActionResult Verify2FA()
        {
            return View();
        }

        [HttpPost]
        public async Task<IActionResult> Verify2FA(string code, [FromServices] IVonageService vonage)
        {
            var requestId = TempData["RequestId"]?.ToString();
            var username = TempData["Username"]?.ToString();
            var password = TempData["Password"]?.ToString();

            if (await vonage.CheckVerificationAsync(requestId, code))
            {
                var user = _context.UserRoles?.FirstOrDefault(u => u.Username == username && u.PasswordHash == password);
                var claims = new List<Claim>
        {
            new Claim(ClaimTypes.Name, user.Username),
            new Claim(ClaimTypes.NameIdentifier, user.EmployeeID.ToString()),
            new Claim(ClaimTypes.Role, user.Role),
            new Claim("UserID", user.UserID.ToString())
        };

                var identity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
                var principal = new ClaimsPrincipal(identity);

                await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, principal);

                HttpContext.Session.SetInt32("EmployeeID", user.EmployeeID);
                HttpContext.Session.SetInt32("UserID", user.UserID);
                HttpContext.Session.SetString("Username", user.Username);
                HttpContext.Session.SetString("Role", user.Role);

                return RedirectToAction("Index", "Dashboard");
            }

            ViewBag.Error = "Invalid verification code.";
            return View();
        }




        public IActionResult ForgotPassword() => View();

        [HttpPost]
        public async Task<IActionResult> ForgotPassword(string email, [FromServices] EmailService emailService)
        {
            var user = await _context.UserRoles.FirstOrDefaultAsync(u => u.EmployeeID == _context.Employees
                .Where(e => e.Email == email)
                .Select(e => e.EmployeeID)
                .FirstOrDefault());

            if (user == null)
            {
                TempData["Error"] = "No account found with that email address.";
                return View();
            }

            // Generate a secure random token
            var token = Convert.ToBase64String(Guid.NewGuid().ToByteArray());
            
            // Store the token in TempData with expiry
            TempData["ResetToken"] = token;
            TempData["ResetEmail"] = email;
            TempData["ResetExpiry"] = DateTime.UtcNow.AddHours(1);

            var resetLink = Url.Action("ResetPassword", "Auth", new { token = token, email = email }, Request.Scheme);

            // Send email with reset link
            var subject = "Password Reset Request";
            var body = $"Please click the following link to reset your password: <a href='{resetLink}'>Reset Password</a>";
            await emailService.SendEmailAsync(email, subject, body);

            TempData["Success"] = "Password reset instructions have been sent to your email.";
            return View();
        }

        public IActionResult ResetPassword(string token, string email)
        {
            if (string.IsNullOrEmpty(token) || string.IsNullOrEmpty(email))
            {
                TempData["Error"] = "Invalid reset link.";
                return RedirectToAction("ForgotPassword");
            }

            // Store the token and email in ViewBag for the form
            ViewBag.Token = token;
            ViewBag.Email = email;
            return View();
        }

        [HttpPost]
        public async Task<IActionResult> ResetPassword(string token, string email, string password, string confirmPassword)
        {
            if (string.IsNullOrEmpty(token) || string.IsNullOrEmpty(email))
            {
                TempData["Error"] = "Invalid reset link.";
                return RedirectToAction("ForgotPassword");
            }

            if (password != confirmPassword)
            {
                TempData["Error"] = "Passwords do not match.";
                ViewBag.Token = token;
                ViewBag.Email = email;
                return View();
            }

            var user = await _context.UserRoles.FirstOrDefaultAsync(u => u.EmployeeID == _context.Employees
                .Where(e => e.Email == email)
                .Select(e => e.EmployeeID)
                .FirstOrDefault());

            if (user == null)
            {
                TempData["Error"] = "User not found.";
                return RedirectToAction("ForgotPassword");
            }

            // Update password
            user.PasswordHash = HashPassword(password);
            await _context.SaveChangesAsync();

            TempData["Success"] = "Your password has been reset successfully. You can now login with your new password.";
            return RedirectToAction("Login");
        }

        public IActionResult OTPVerification() => View();
        public IActionResult AccessDenied()
        {
            return View();
        }

        [HttpPost]
        public async Task<IActionResult> Logout()
        {
            await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            return RedirectToAction("Login", "Auth");
        }

    }

    public class BaseController : Controller
    {
        protected readonly AppDbContext _context;

        public BaseController(AppDbContext context)
        {
            _context = context;
        }

        protected bool IsUserAuthenticated()
        {
            return HttpContext.Session.GetInt32("UserID") != null && 
                   HttpContext.Session.GetInt32("EmployeeID") != null;
        }

        protected IActionResult RedirectToLogin()
        {
            return RedirectToAction("Login", "Auth");
        }

        protected async Task LogAudit(int userId, string action)
        {
            var audit = new AuditLog
            {
                UserID = userId,
                ActionTaken = action,
                Timestamp = DateTime.Now,
                IPAddress = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "Unknown"
            };

            _context.AuditLogs.Add(audit);
            await _context.SaveChangesAsync();
        }
    }

    [Authorize(Roles = "HR, Employee, Admin, PayrollStaff")]
    public class DashboardController : BaseController
    {
        private readonly ILogger<DashboardController> _logger;

        public DashboardController(ILogger<DashboardController> logger, AppDbContext context) : base(context)
        {
            _logger = logger;
        }

        public async Task<IActionResult> Index()
        {
            if (!IsUserAuthenticated())
            {
                return RedirectToLogin();
            }

            var user = HttpContext.Session.GetInt32("UserID");
            var employeeID = HttpContext.Session.GetInt32("EmployeeID");

            if (employeeID == null || user == null)
            {
                return RedirectToAction("Login", "Auth");
            }

            // Get employee's department and salary info
            var employee = await _context.Employees
                .Include(e => e.Department)
                .Include(e => e.SalaryGrade)
                .FirstOrDefaultAsync(e => e.EmployeeID == employeeID);

            if (employee == null)
            {
                return RedirectToAction("Login", "Auth");
            }

            var today = DateTime.Today;
            var startOfMonth = new DateTime(today.Year, today.Month, 1);
            var endOfMonth = startOfMonth.AddMonths(1).AddDays(-1);

            // Get today's attendance
            var attendance = await _context.Attendances
                .FirstOrDefaultAsync(a => a.EmployeeID == employeeID && a.Date == today);

            // Get relevant announcements
            var announcements = await _context.Announcements
                .Where(a => (a.TargetType == "All" || a.TargetType == employee.Department.DepartmentName) && 
                           (a.ExpiryDate == null || a.ExpiryDate > DateTime.Now))
                .OrderByDescending(a => a.DatePosted)
                .Take(5)
                .ToListAsync();

            // Calculate time log data for current month
            var monthlyAttendance = await _context.Attendances
                .Where(a => a.EmployeeID == employeeID && 
                           a.Date >= startOfMonth && 
                           a.Date <= endOfMonth)
                .ToListAsync();

            // Calculate monthly statistics
            var totalHours = monthlyAttendance.Sum(a => a.TotalHoursWorked ?? 0);
            var scheduledHours = 8m * DateTime.DaysInMonth(today.Year, today.Month);
            var shortageHours = Math.Max(0, scheduledHours - totalHours);
            var overtimeHours = monthlyAttendance.Sum(a => a.OvertimeHours ?? 0);
            var workedTimeHours = totalHours;

            // Calculate today's worked hours and balance
            TimeSpan? workedHours = null;
            TimeSpan? balanceHours = null;
            if (attendance?.CheckInTime != null)
            {
                if (attendance.CheckOutTime != null)
                {
                    workedHours = attendance.CheckOutTime.Value - attendance.CheckInTime.Value;
                }
                else
                {
                    workedHours = DateTime.Now.TimeOfDay - attendance.CheckInTime.Value;
                }
                balanceHours = new TimeSpan(8, 0, 0) - workedHours.Value;
            }

            // Get leave statistics
            var leaveStats = await _context.Leaves
                .Where(l => l.EmployeeID == employeeID)
                .ToListAsync();

            var totalLeaveTaken = leaveStats.Count(l => l.ApprovalStatus == "Approved");
            var pendingLeaveRequests = leaveStats.Count(l => l.ApprovalStatus == "Pending");
            var totalLeaveAllowance = 20; // Assuming 20 days annual leave
            var leaveBalance = totalLeaveAllowance - totalLeaveTaken;

            // Get payroll information
            var lastPayroll = await _context.Payrolls
                .Where(p => p.EmployeeID == employeeID)
                .OrderByDescending(p => p.PayPeriod)
                .FirstOrDefaultAsync();

            // Calculate days until next payroll (assuming 15th and last day of month)
            var nextPayrollDate = today.Day <= 15 
                ? new DateTime(today.Year, today.Month, 15)
                : new DateTime(today.Year, today.Month, DateTime.DaysInMonth(today.Year, today.Month));
            var daysUntilNextPayroll = (nextPayrollDate - today).Days;

            // Calculate attendance statistics
            var presentDays = monthlyAttendance.Count(a => a.AttendanceStatus == "Present");
            var absentDays = monthlyAttendance.Count(a => a.AttendanceStatus == "Absent");
            var lateDays = monthlyAttendance.Count(a => a.CheckInTime > new TimeSpan(8, 0, 0));
            var attendanceRate = (decimal)presentDays / DateTime.DaysInMonth(today.Year, today.Month) * 100;

            var viewModel = new DashboardViewModel
            {
                Announcements = announcements,
                CheckInTime = attendance?.CheckInTime,
                CheckOutTime = attendance?.CheckOutTime,
                WorkedHours = workedHours,
                BalanceHours = balanceHours,
                TotalHours = scheduledHours,
                ShortageHours = shortageHours,
                OvertimeHours = overtimeHours,
                WorkedTimeHours = workedTimeHours,
                
                // Leave Statistics
                TotalLeaveAllowance = totalLeaveAllowance,
                TotalLeaveTaken = totalLeaveTaken,
                LeaveBalance = leaveBalance,
                PendingLeaveRequests = pendingLeaveRequests,

                // Payroll Information
                CurrentSalary = employee.SalaryGrade?.BasicSalary ?? 0,
                LastPayrollAmount = lastPayroll?.NetSalary ?? 0,
                LastPayrollDate = lastPayroll?.PayPeriod,
                DaysUntilNextPayroll = daysUntilNextPayroll,

                // Attendance Statistics
                PresentDaysThisMonth = presentDays,
                AbsentDaysThisMonth = absentDays,
                LateDaysThisMonth = lateDays,
                AttendanceRate = attendanceRate
            };

            return View(viewModel);
        }
    }

    [Authorize(Roles = "HR, Admin")]
    public class EmployeesController : BaseController
    {
    
        private readonly AuditLogService _audit;
        public EmployeesController(AppDbContext context, AuditLogService audit) : base(context)
        {
            _audit = audit;
        }

        public async Task<IActionResult> Index(int page = 1, int pageSize = 10, string? search = null)
        {
            if (!IsUserAuthenticated())
            {
                return RedirectToLogin();
            }

            var employeeQuery = _context.Employees
                .Where(e => e.EmploymentStatus != "Inactive")
                .Include(e => e.Position)
                .Include(e => e.Department)
                .AsQueryable();

            if (!string.IsNullOrEmpty(search))
            {
                employeeQuery = employeeQuery.Where(e =>
                    e.FirstName.Contains(search) ||
                    e.LastName.Contains(search) ||
                    (e.Department != null && e.Department.DepartmentName.Contains(search))
                );
            }

            var totalEmployees = await employeeQuery.CountAsync();
            var totalPages = (int)Math.Ceiling(totalEmployees / (double)pageSize);

            var employees = await employeeQuery
                .Skip((page - 1) * pageSize)
                .Take(pageSize)
                .Select(e => new
                {
                    e.EmployeeID,
                    e.FirstName,
                    e.LastName,
                    e.Gender,
                    e.BirthDate,
                    e.ContactNumber,
                    e.Email,
                    e.HireDate,
                    e.Address,
                    e.EmploymentStatus,
                    PositionTitle = e.Position != null ? e.Position.PositionTitle : "N/A",
                    DepartmentName = e.Department != null ? e.Department.DepartmentName : "N/A"
                })
                .ToListAsync();

            ViewBag.Employees = employees;
            ViewBag.CurrentPage = page;
            ViewBag.TotalPages = totalPages;
            ViewBag.SearchQuery = search;

            return View();
        }



        public IActionResult Create()
        {
            if (!IsUserAuthenticated())
            {
                return RedirectToLogin();
            }

            var departments = _context.Departments?.ToList();
            var positions = _context.Positions?.ToList();
            var salary = _context.SalaryGrades?.ToList();

            ViewBag.Departments = departments;
            ViewBag.Positions = positions;
            ViewBag.SalaryGrades = salary;

            return View();
        }



        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Create(Employee employee)  // Add async and Task<IActionResult>
        {
            if (!ModelState.IsValid)
            {
                ViewBag.Departments = _context.Departments?.ToList();
                ViewBag.Positions = _context.Positions?.ToList();
                ViewBag.SalaryGrades = _context.SalaryGrades?.ToList();
                return View("Create", employee);
            }

            try
            {
                // Set default values
                employee.EmploymentStatus = "Active";
                employee.PagIbigDoc = "--";
                employee.SSSDoc = "--";
                employee.PhilHealthDoc = "--";
                employee.BirthCertificateDoc = "--";

                _context.Employees.Add(employee);
                await _context.SaveChangesAsync();  // Change to async save
                
                var userID = HttpContext.Session.GetInt32("UserID");
                await LogAudit(userID ?? 0, $"Created new employee: {employee.FirstName} {employee.LastName} (ID: {employee.EmployeeID})");

                TempData["Success"] = "Employee added successfully!";
                return RedirectToAction("Index", "Employees");
            }
            catch (Exception ex)
            {
                TempData["Error"] = "An error occurred while adding the employee.";
                ViewBag.Departments = _context.Departments?.ToList();
                ViewBag.Positions = _context.Positions?.ToList();
                ViewBag.SalaryGrades = _context.SalaryGrades?.ToList();
                return View("Create", employee);
            }
        }





        // Show Edit Employee Form
        public IActionResult Edit(int id)
        {
            var employee = _context.Employees.FirstOrDefault(e => e.EmployeeID == id);
            if (employee == null) return NotFound();

            ViewBag.Departments = _context.Departments
                .Select(d => new SelectListItem
                {
                    Value = d.DepartmentID.ToString(),
                    Text = d.DepartmentName
                }).ToList();

            ViewBag.Positions = _context.Positions
                .Select(p => new SelectListItem
                {
                    Value = p.PositionID.ToString(),
                    Text = p.PositionTitle
                }).ToList();

            ViewBag.SalaryGrades = _context.SalaryGrades
                .Select(s => new SelectListItem
                {
                    Value = s.SalaryGradeID.ToString(),
                    Text = (s.BasicSalary ?? 0).ToString("N2")
                }).ToList();

            return View(employee);
        }

        // Handle Employee Update
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Edit(int id, Employee updatedEmployee)
        {
            if (id != updatedEmployee.EmployeeID) return NotFound();

            if (!ModelState.IsValid) return View(updatedEmployee);

            try
            {
                _context.Employees.Update(updatedEmployee);
                await _context.SaveChangesAsync();

                var userID = HttpContext.Session.GetInt32("UserID");
                await LogAudit(userID ?? 0, $"Updated employee: {updatedEmployee.FirstName} {updatedEmployee.LastName} (ID: {updatedEmployee.EmployeeID})");

                TempData["Success"] = "Employee updated successfully!";
                return RedirectToAction(nameof(Index));
            }
            catch (Exception ex)
            {
                TempData["Error"] = "An error occurred while updating the employee.";
                return View(updatedEmployee);
            }
        }

        // Show Employee Details
        public IActionResult Details(int id)
        {
            var employee = _context.Employees
                .Include(e => e.Department)
                .Include(e => e.Position)
                .Include(e => e.SalaryGrade)
                .FirstOrDefault(e => e.EmployeeID == id);

            if (employee == null) return NotFound();

            return View(employee);
        }

        // Handle Employee Deletion
        [HttpGet]
        public async Task<IActionResult> Inactive(int id)
        {
            var employee = _context.Employees.FirstOrDefault(e => e.EmployeeID == id);
            if (employee == null)
            {
                TempData["Error"] = "Employee not found.";
                return RedirectToAction(nameof(Index));
            }

            try
            {
                employee.EmploymentStatus = "Inactive";
                await _context.SaveChangesAsync();

                var userID = HttpContext.Session.GetInt32("UserID");
                await LogAudit(userID ?? 0, $"Deactivated employee: {employee.FirstName} {employee.LastName} (ID: {employee.EmployeeID})");

                TempData["Success"] = "Employee marked as Inactive.";
            }
            catch (Exception ex)
            {
                TempData["Error"] = "An error occurred while updating the employee status.";
            }

            return RedirectToAction(nameof(Index));
        }

    }



    [Authorize(Roles = "HR, Employee, Admin, PayrollStaff")]
    public class PayrollController : BaseController
    {
        private readonly EmailService _emailService;
        private readonly AuditLogService _audit;
        private readonly IConfiguration _configuration;

        public PayrollController(EmailService emailService, AppDbContext context, AuditLogService audit, IConfiguration configuration) : base(context)
        {
            _emailService = emailService;
            _audit = audit;
            _configuration = configuration;
        }




        // Payroll List Page


        public async Task<IActionResult> Index(int page = 1, string searchString = "", string statusFilter = "", int? monthFilter = null, int? yearFilter = null)
        {
            if (!IsUserAuthenticated())
            {
                return RedirectToLogin();
            }

            int pageSize = 10;

            var currentMonth = DateTime.Now.Month;
            var currentYear = DateTime.Now.Year;

            // Check if payroll has already been processed for the current month
            bool alreadyProcessed = await _context.Payrolls
                .AnyAsync(p => p.DateProcessed!.Value.Month == currentMonth && p.DateProcessed.Value.Year == currentYear);

            ViewBag.CanGeneratePayroll = !alreadyProcessed;

            var payrollQuery = _context.Payrolls
                .Include(p => p.Employee)
                .Include(p => p.SalaryGrade)
                .AsQueryable();

            // Apply filters
            if (!string.IsNullOrEmpty(searchString))
            {
                payrollQuery = payrollQuery.Where(p => 
                    (p.Employee.FirstName + " " + p.Employee.LastName).Contains(searchString));
            }

            if (!string.IsNullOrEmpty(statusFilter))
            {
                payrollQuery = payrollQuery.Where(p => p.PayrollStatus == statusFilter);
            }

            if (monthFilter.HasValue)
            {
                payrollQuery = payrollQuery.Where(p => p.PayPeriod.Value.Month == monthFilter.Value);
            }

            if (yearFilter.HasValue)
            {
                payrollQuery = payrollQuery.Where(p => p.PayPeriod.Value.Year == yearFilter.Value);
            }

            // Order by PayPeriod in descending order (latest first)
            payrollQuery = payrollQuery.OrderByDescending(p => p.PayPeriod);

            int totalItems = await payrollQuery.CountAsync();
            int totalPages = (int)Math.Ceiling((double)totalItems / pageSize);

            // Ensure page is within valid range
            page = Math.Max(1, Math.Min(page, totalPages > 0 ? totalPages : 1));

            var payrolls = await payrollQuery
                .Skip((page - 1) * pageSize)
                .Take(pageSize)
                .ToListAsync();

            // Set ViewBag properties for the filters
            ViewBag.CurrentSearch = searchString;
            ViewBag.CurrentStatus = statusFilter;
            ViewBag.CurrentMonth = monthFilter;
            ViewBag.CurrentYear = yearFilter;
            ViewBag.CurrentPage = page;
            ViewBag.TotalPages = totalPages > 0 ? totalPages : 1;

            return View(payrolls);
        }






        public async Task<IActionResult> ExportReport()
        {
            var payrolls = await _context.Payrolls
             .Include(p => p.Employee)
             .Include(p => p.SalaryGrade)
             .OrderBy(p => p.DateProcessed)
             .ToListAsync();

            var csvContent = new StringBuilder();
            csvContent.AppendLine("Employee,Pay Period,Basic Salary,Allowance,Deductions,Net Pay,Status");

            foreach (var p in payrolls)
            {
                var deductions = (p.Deductions_SSS ?? 0) + (p.Deductions_PhilHealth ?? 0) + (p.Deductions_PagIbig ?? 0) + (p.Absences ?? 0) + (p.TaxWithHolding ?? 0);
                var netPay = p?.NetSalary ?? 0;

                csvContent.AppendLine($"{p.Employee?.FirstName} {p.Employee?.LastName},{p.PayPeriod?.ToString("MMMM yyyy")},{p.SalaryGrade?.BasicSalary:N2},{p.SalaryGrade?.Allowances:N2},{deductions:N2},{netPay:N2},{(p.PayrollStatus == "Processed" ? "Processed" : "Pending")}");
            }

            var fileName = "PayrollReport_" + DateTime.Now.ToString("yyyyMMdd") + ".csv";
            var fileBytes = Encoding.UTF8.GetBytes(csvContent.ToString());

            // Add headers to make the file read-only
            Response.Headers.Add("Content-Disposition", $"attachment; filename=\"{fileName}\"");
            Response.Headers.Add("Content-Type", "text/csv");
            Response.Headers.Add("X-Content-Type-Options", "nosniff");
            Response.Headers.Add("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0");
            Response.Headers.Add("Pragma", "no-cache");
            Response.Headers.Add("Expires", "0");
            Response.Headers.Add("Content-Transfer-Encoding", "binary");
            Response.Headers.Add("Content-Length", fileBytes.Length.ToString());

            var userID = HttpContext.Session.GetInt32("UserID");
            await LogAudit(userID ?? 0, $"Exported payroll report");

            return File(fileBytes, "text/csv", fileName);
        }



        private const int PageSize = 10;


        public async Task<IActionResult> MyPayroll(int page = 1, int pageSize = 10, int? monthFilter = null, int? yearFilter = null)
        {
            int? employeeId = HttpContext.Session.GetInt32("EmployeeID");
            if (employeeId == null)
                return RedirectToAction("Login", "Auth");

            var query = _context.Payrolls
                .Include(p => p.SalaryGrade)
                .Where(p => p.EmployeeID == employeeId);

            // Apply month filter
            if (monthFilter.HasValue)
            {
                query = query.Where(p => p.PayPeriod.Value.Month == monthFilter.Value);
            }

            // Apply year filter
            if (yearFilter.HasValue)
            {
                query = query.Where(p => p.PayPeriod.Value.Year == yearFilter.Value);
            }

            // Order by PayPeriod in descending order (latest first)
            query = query.OrderByDescending(p => p.PayPeriod);

            int totalRecords = await query.CountAsync();
            int totalPages = (int)Math.Ceiling((double)totalRecords / pageSize);

            // Ensure page is within valid range
            page = Math.Max(1, Math.Min(page, totalPages > 0 ? totalPages : 1));

            var data = await query
                .Skip((page - 1) * pageSize)
                .Take(pageSize)
                .ToListAsync();

            ViewBag.CurrentPage = page;
            ViewBag.TotalPages = totalPages > 0 ? totalPages : 1;
            ViewBag.CurrentMonth = monthFilter;
            ViewBag.CurrentYear = yearFilter;

            return View(data);
        }




        public async Task<IActionResult> TestEmail()
        {
            await _emailService.SendEmailAsync("arvinduble143@gmail.com", "Test", "This is a test email from HR System.");
            return Content("Email Sent!");
        }

        [HttpGet]
        public async Task<IActionResult> SendEmail(int id)
        {
            var payroll = await _context.Payrolls
                .Include(p => p.Employee)
                .Include(p => p.SalaryGrade)
                .FirstOrDefaultAsync(p => p.PayrollID == id);

            if (payroll == null)
            {
                TempData["Message"] = "Payroll not found.";
                return RedirectToAction("Index");
            }

            var employee = payroll.Employee;
            if (employee == null || string.IsNullOrEmpty(employee.Email))
            {
                TempData["Message"] = "Employee email is missing.";
                return RedirectToAction("Index");
            }

            // Compose email content
            string subject = $"Your Payslip for {payroll.PayPeriod?.ToString("MMMM yyyy")}";
            string message = $@"
                <p>Dear {employee.FirstName},</p>

                <p>We are pleased to provide you with your payslip summary for the period of <strong>{payroll.PayPeriod?.ToString("MMMM yyyy")}</strong>.</p>

                <table style='border-collapse: collapse; width: 100%; max-width: 600px;'>
                    <tr style='background-color: #f2f2f2;'>
                        <th style='padding: 8px; border: 1px solid #ddd;'>Description</th>
                        <th style='padding: 8px; border: 1px solid #ddd;'>Amount (₱)</th>
                    </tr>
                    <tr>
                        <td style='padding: 8px; border: 1px solid #ddd;'>Basic Salary</td>
                        <td style='padding: 8px; border: 1px solid #ddd;'>{payroll.SalaryGrade?.BasicSalary:N2}</td>
                    </tr>
                    <tr>
                        <td style='padding: 8px; border: 1px solid #ddd;'>Allowances</td>
                        <td style='padding: 8px; border: 1px solid #ddd;'>{payroll.SalaryGrade?.Allowances:N2}</td>
                    </tr>
                    <tr>
                        <td style='padding: 8px; border: 1px solid #ddd;'>Deductions (SSS, PhilHealth, Pag-IBIG, Absences, Tax)</td>
                        <td style='padding: 8px; border: 1px solid #ddd;'>{(payroll.Deductions_SSS + payroll.Deductions_PhilHealth + payroll.Deductions_PagIbig + payroll.Absences + payroll.TaxWithHolding):N2}</td>
                    </tr>
                    <tr style='font-weight: bold; background-color: #e0ffe0;'>
                        <td style='padding: 8px; border: 1px solid #ddd;'>Net Pay</td>
                        <td style='padding: 8px; border: 1px solid #ddd;'>{payroll.NetSalary:N2}</td>
                    </tr>
                </table>

                <p>If you have any questions or concerns, feel free to reach out to the HR department.</p>

                <p>Best regards,<br/>HR Department<br/>{DateTime.Now:MMMM dd, yyyy}</p>
                ";

            try
            {
                await _emailService.SendEmailAsync(employee.Email, subject, message);

                // ✅ Update status to Processed
                payroll.PayrollStatus = "Processed";
                _context.Update(payroll);
                await _context.SaveChangesAsync();

                var userID = HttpContext.Session.GetInt32("UserID");
                await LogAudit(userID ?? 0, $"Payslip emailed to {employee.Email} and marked as Processed.");

                TempData["Message"] = $"Payslip emailed to {employee.Email} and marked as Processed.";
            }
            catch (Exception ex)
            {
                TempData["Message"] = $"Error sending email: {ex.Message}";
            }

            return RedirectToAction("Index");
        }



        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> GenerateSemiMonthlyPayroll(int selectedMonth, int half)
        {
            var currentYear = DateTime.Now.Year;

            // Set pay period range based on the half (1st or 2nd)
            var (startDate, endDate) = half == 1
                ? (new DateTime(currentYear, selectedMonth, 1), new DateTime(currentYear, selectedMonth, 15))
                : (new DateTime(currentYear, selectedMonth, 16), new DateTime(currentYear, selectedMonth, DateTime.DaysInMonth(currentYear, selectedMonth)));

            try
            {
                // Check if the current date is before the selected period start date
                if (DateTime.Now < endDate)
                {
                    TempData["ErrorMessage"] = "Cannot generate payroll for a future period. Please ensure the selected period has passed.";
                    return RedirectToAction("Index");
                }

                // Prevent duplicate payroll processing
                bool alreadyProcessed = await _context.Payrolls
                .AnyAsync(p => p.PayPeriod == startDate && (p.PayrollStatus == "Generated" || p.PayrollStatus == "Processed"));


                if (alreadyProcessed)
                {
                    TempData["Message"] = $"Payroll already processed for {startDate:MMMM yyyy} ({(half == 1 ? "1st Half" : "2nd Half")}).";
                    return RedirectToAction("Index");
                }

                var employees = await _context.Employees
                    .Include(e => e.SalaryGrade)
                    .Where(e => e.EmploymentStatus == "Active" && e.SalaryGradeID != null)
                    .ToListAsync();

                var processorId = HttpContext.Session.GetInt32("UserID");

                foreach (var emp in employees)
                {
                    var attendance = await _context.Attendances
                        .Where(a => a.EmployeeID == emp.EmployeeID &&
                                    a.Date >= startDate &&
                                    a.Date <= endDate)
                        .ToListAsync();

                    // Basic compensation
                    decimal fullBasic = emp.SalaryGrade?.BasicSalary ?? 0;
                    decimal halfMonthBasic = fullBasic / 2;

                    // Allowances are assumed fixed per cutoff
                    decimal allowances = emp.SalaryGrade?.Allowances ?? 0;

                    // Overtime pay
                    decimal overtimeHours = attendance.Sum(a => a.OvertimeHours ?? 0);
                    decimal overtimeRate = emp.SalaryGrade?.OvertimeRate ?? 0;
                    decimal overtimePay = overtimeHours * overtimeRate;

                    // Semi-monthly gross
                    decimal gross = halfMonthBasic + allowances + overtimePay;

                    // Absence deduction (based on estimated working days per cutoff)
                    int workingDays = 11;
                    int presentDays = attendance.Count(a => a.AttendanceStatus == "Present" || a.AttendanceStatus == "Late");
                    int absentDays = workingDays - presentDays;
                    decimal perDayRate = halfMonthBasic / workingDays;
                    decimal absenceDeduction = absentDays * perDayRate;

                    // Mandatory deductions (semi-monthly)
                    // SSS: 4.5% of monthly salary credit (MSC) up to 30,000
                    decimal sssMSC = Math.Min(fullBasic, 30000);
                    decimal sss = sssMSC * 0.045m / 2;

                    // PhilHealth: 2.5% of monthly basic salary, minimum 10,000, maximum 100,000
                    decimal philHealthMSC = Math.Clamp(fullBasic, 10000, 100000);
                    decimal philHealth = philHealthMSC * 0.025m / 2;

                    // Pag-IBIG: 2% of monthly basic salary, maximum 5,000
                    decimal pagibigMSC = Math.Min(fullBasic, 5000);
                    decimal pagibig = pagibigMSC * 0.02m / 2;

                    // Tax computation (TRAIN Law)
                    decimal monthlyGross = gross * 2; // Convert semi-monthly to monthly
                    decimal annualGross = monthlyGross * 12; // Convert monthly to annual

                    decimal ComputeWithholdingTax(decimal annualIncome)
                    {
                        if (annualIncome <= 250000) return 0;
                        else if (annualIncome <= 400000) return (annualIncome - 250000) * 0.20m;
                        else if (annualIncome <= 800000) return 30000 + ((annualIncome - 400000) * 0.25m);
                        else if (annualIncome <= 2000000) return 130000 + ((annualIncome - 800000) * 0.30m);
                        else if (annualIncome <= 8000000) return 490000 + ((annualIncome - 2000000) * 0.32m);
                        else return 2410000 + ((annualIncome - 8000000) * 0.35m);
                    }

                    decimal annualTax = ComputeWithholdingTax(annualGross);
                    decimal monthlyTax = annualTax / 12;
                    decimal tax = monthlyTax / 2; // Convert to semi-monthly

                    // Total deductions
                    decimal totalDeductions = sss + philHealth + pagibig + tax + absenceDeduction;

                    // Net salary
                    decimal net = gross - totalDeductions;

                    // Save to payroll table
                    var payroll = new Payroll
                    {
                        EmployeeID = emp.EmployeeID,
                        SalaryGradeID = emp.SalaryGradeID ?? 0,
                        PayPeriod = startDate,
                        GrossSalary = gross,
                        Deductions_SSS = sss,
                        Deductions_PhilHealth = philHealth,
                        Deductions_PagIbig = pagibig,
                        Absences = absenceDeduction,
                        TaxWithHolding = tax,
                        NetSalary = net,
                        PayrollStatus = "Generated",
                        DateProcessed = DateTime.Now,
                        ProcessedBy = processorId
                    };

                    _context.Payrolls.Add(payroll);
                }

                await _context.SaveChangesAsync();

                var userID = HttpContext.Session.GetInt32("UserID");
                await LogAudit(userID ?? 0, $"Generated payroll for {startDate:MMMM yyyy} ({(half == 1 ? "1st Half" : "2nd Half")})");

                TempData["Message"] = $"Payroll for {startDate:MMMM yyyy} ({(half == 1 ? "1st Half" : "2nd Half")}) generated successfully.";

                return RedirectToAction("Index");
            }
            catch (Exception ex)
            {
                TempData["ErrorMessage"] = "An error occurred while generating the payroll. Please try again later.";
                // Log the exception details here for debugging
                Console.Error.WriteLine($"Error generating payroll: {ex.Message}");
                return RedirectToAction("Index");
            }
        }


        [Authorize(Roles = "HR")]
        public async Task<IActionResult> ComputePayroll(int id)
        {
            if (!IsUserAuthenticated())
            {
                return RedirectToLogin();
            }

            var employee = await _context.Employees
                .Include(e => e.SalaryGrade)
                .FirstOrDefaultAsync(e => e.EmployeeID == id);

            if (employee == null)
            {
                return NotFound();
            }

            var currentMonth = DateTime.Now.Month;
            var currentYear = DateTime.Now.Year;
            var startDate = new DateTime(currentYear, currentMonth, 1);
            var endDate = new DateTime(currentYear, currentMonth, 15); // First half of the month

            // Get attendance for the period
            var attendance = await _context.Attendances
                .Where(a => a.EmployeeID == employee.EmployeeID &&
                           a.Date >= startDate &&
                           a.Date <= endDate)
                .ToListAsync();

            // Basic compensation
            decimal fullBasic = employee.SalaryGrade?.BasicSalary ?? 0;
            decimal halfMonthBasic = fullBasic / 2;

            // Allowances are assumed fixed per cutoff
            decimal allowances = employee.SalaryGrade?.Allowances ?? 0;

            // Overtime pay
            decimal overtimeHours = attendance.Sum(a => a.OvertimeHours ?? 0);
            decimal overtimeRate = employee.SalaryGrade?.OvertimeRate ?? 0;
            decimal overtimePay = overtimeHours * overtimeRate;

            // Semi-monthly gross
            decimal gross = halfMonthBasic + allowances + overtimePay;

            // Absence deduction (based on estimated working days per cutoff)
            int workingDays = 11;
            int presentDays = attendance.Count(a => a.AttendanceStatus == "Present" || a.AttendanceStatus == "Late");
            int absentDays = workingDays - presentDays;
            decimal perDayRate = halfMonthBasic / workingDays;
            decimal absenceDeduction = absentDays * perDayRate;

            // Mandatory deductions (semi-monthly)
            // SSS: 4.5% of monthly salary credit (MSC) up to 30,000
            decimal sssMSC = Math.Min(fullBasic, 30000);
            decimal sss = sssMSC * 0.045m / 2;

            // PhilHealth: 2.5% of monthly basic salary, minimum 10,000, maximum 100,000
            decimal philHealthMSC = Math.Clamp(fullBasic, 10000, 100000);
            decimal philHealth = philHealthMSC * 0.025m / 2;

            // Pag-IBIG: 2% of monthly basic salary, maximum 5,000
            decimal pagibigMSC = Math.Min(fullBasic, 5000);
            decimal pagibig = pagibigMSC * 0.02m / 2;

            // Tax computation (TRAIN Law)
            decimal monthlyGross = gross * 2; // Convert semi-monthly to monthly
            decimal annualGross = monthlyGross * 12; // Convert monthly to annual

            decimal ComputeWithholdingTax(decimal annualIncome)
            {
                if (annualIncome <= 250000) return 0;
                else if (annualIncome <= 400000) return (annualIncome - 250000) * 0.20m;
                else if (annualIncome <= 800000) return 30000 + ((annualIncome - 400000) * 0.25m);
                else if (annualIncome <= 2000000) return 130000 + ((annualIncome - 800000) * 0.30m);
                else if (annualIncome <= 8000000) return 490000 + ((annualIncome - 2000000) * 0.32m);
                else return 2410000 + ((annualIncome - 8000000) * 0.35m);
            }

            decimal annualTax = ComputeWithholdingTax(annualGross);
            decimal monthlyTax = annualTax / 12;
            decimal tax = monthlyTax / 2; // Convert to semi-monthly

            // Total deductions
            decimal totalDeductions = sss + philHealth + pagibig + tax + absenceDeduction;

            // Net salary
            decimal net = gross - totalDeductions;

            var viewModel = new PayrollViewModel
            {
                EmployeeID = employee.EmployeeID,
                EmployeeName = $"{employee.FirstName} {employee.LastName}",
                SalaryGradeID = employee.SalaryGradeID,
                BasicSalary = halfMonthBasic,
                Allowances = allowances,
                OvertimeHours = overtimeHours,
                OvertimeRate = overtimeRate,
                OvertimePay = overtimePay,
                GrossSalary = gross,
                AbsenceDeduction = absenceDeduction,
                Deductions_SSS = sss,
                Deductions_PhilHealth = philHealth,
                Deductions_PagIbig = pagibig,
                WithholdingTax = tax,
                TotalDeductions = totalDeductions,
                NetSalary = net,
                PayPeriod = startDate,
                PayrollStatus = "Generated"
            };

            return View(viewModel);
        }

        public async Task<IActionResult> Payslip(int id)
        {
            // Retrieve the payroll record
            var payroll = await _context.Payrolls
                .Include(p => p.Employee)
                    .ThenInclude(e => e.SalaryGrade)
                .FirstOrDefaultAsync(p => p.PayrollID == id);

            if (payroll == null)
            {
                return NotFound();
            }

            var emp = payroll.Employee;

            if (emp == null || emp.SalaryGradeID == null)
            {
                return BadRequest("Invalid employee or missing salary grade.");
            }

            // Use the payroll's pay period for attendance and salary calculations
            var payPeriod = payroll.PayPeriod ?? DateTime.Now;
            int workingDays = 11;
            DateTime startDate, endDate;
            if (payPeriod.Day <= 15)
            {
                // 1st half
                startDate = new DateTime(payPeriod.Year, payPeriod.Month, 1);
                endDate = new DateTime(payPeriod.Year, payPeriod.Month, 15);
            }
            else
            {
                // 2nd half
                startDate = new DateTime(payPeriod.Year, payPeriod.Month, 16);
                endDate = new DateTime(payPeriod.Year, payPeriod.Month, DateTime.DaysInMonth(payPeriod.Year, payPeriod.Month));
            }

            var attendance = await _context.Attendances
                .Where(a => a.EmployeeID == emp.EmployeeID && a.Date >= startDate && a.Date <= endDate)
                .ToListAsync();

            decimal fullBasic = emp.SalaryGrade?.BasicSalary ?? 0;
            decimal halfMonthBasic = fullBasic / 2;
            decimal allowances = emp.SalaryGrade?.Allowances ?? 0;
            decimal overtimeHours = attendance.Sum(a => a.OvertimeHours ?? 0);
            decimal overtimeRate = emp.SalaryGrade?.OvertimeRate ?? 0;
            decimal overtimePay = overtimeHours * overtimeRate;
            decimal gross = halfMonthBasic + allowances + overtimePay;

            int presentDays = attendance.Count(a => a.AttendanceStatus == "Present" || a.AttendanceStatus == "Late");
            int absentDays = workingDays - presentDays;
            decimal perDayRate = halfMonthBasic / workingDays;
            decimal absenceDeduction = absentDays * perDayRate;

            decimal sssMSC = Math.Min(fullBasic, 30000);
            decimal sss = sssMSC * 0.045m / 2;
            decimal philHealthMSC = Math.Clamp(fullBasic, 10000, 100000);
            decimal philHealth = philHealthMSC * 0.025m / 2;
            decimal pagibigMSC = Math.Min(fullBasic, 5000);
            decimal pagibig = pagibigMSC * 0.02m / 2;

            decimal monthlyGross = gross * 2;
            decimal annualGross = monthlyGross * 12;
            decimal ComputeWithholdingTax(decimal annualIncome)
            {
                if (annualIncome <= 250000) return 0;
                else if (annualIncome <= 400000) return (annualIncome - 250000) * 0.20m;
                else if (annualIncome <= 800000) return 30000 + ((annualIncome - 400000) * 0.25m);
                else if (annualIncome <= 2000000) return 130000 + ((annualIncome - 800000) * 0.30m);
                else if (annualIncome <= 8000000) return 490000 + ((annualIncome - 2000000) * 0.32m);
                else return 2410000 + ((annualIncome - 8000000) * 0.35m);
            }
            decimal annualTax = ComputeWithholdingTax(annualGross);
            decimal monthlyTax = annualTax / 12;
            decimal tax = monthlyTax / 2;

            decimal totalDeductions = sss + philHealth + pagibig + tax + absenceDeduction;
            decimal net = gross - totalDeductions;

            // Get current user
            int? processorId = HttpContext.Session.GetInt32("UserID");
            var processor = await _context.UserRoles.FindAsync(processorId);

            var viewModel = new PayrollViewModel
            {
                PayrollId = payroll.PayrollID,
                EmployeeID = emp.EmployeeID,
                EmployeeName = $"{emp.FirstName} {emp.LastName}",
                SalaryGradeID = emp.SalaryGradeID,
                BasicSalary = halfMonthBasic,
                Allowances = allowances,
                OvertimeHours = overtimeHours,
                OvertimeRate = overtimeRate,
                OvertimePay = overtimePay,
                GrossSalary = gross,
                AbsenceDeduction = absenceDeduction,
                Deductions_SSS = sss,
                Deductions_PhilHealth = philHealth,
                Deductions_PagIbig = pagibig,
                WithholdingTax = tax,
                TotalDeductions = totalDeductions,
                NetSalary = net,
                PayPeriod = payroll.PayPeriod,
                PayrollStatus = payroll.PayrollStatus,
                ProcessedByUser = processor
            };

            return View(viewModel);
        }

        [HttpGet]
        public async Task<IActionResult> ReimbursePayroll(int id)
        {
            var payroll = await _context.Payrolls
                .Include(p => p.Employee)
                .FirstOrDefaultAsync(p => p.PayrollID == id);

            if (payroll == null || payroll.Employee == null)
                return NotFound();

            // Check if payroll is already processed
            if (payroll.PayrollStatus == "Processed")
            {
                TempData["ErrorMessage"] = "This payroll has already been processed and reimbursed.";
                return RedirectToAction("Index");
            }

            // Sandbox: Replace with your sandbox PayPal access token (use a helper or service to get this dynamically)
            string accessToken = await GetPayPalAccessTokenAsync();

            var payoutRequest = new
            {
                sender_batch_header = new
                {
                    sender_batch_id = Guid.NewGuid().ToString(),
                    email_subject = "Payroll Reimbursement"
                },
                items = new[]
                {
            new
            {
                recipient_type = "EMAIL",
                amount = new { value = "1.00", currency = "PHP" },
                note = $"Payroll reimbursement for {payroll.Employee.FirstName}",
                receiver = payroll.Employee.Email,
                sender_item_id = $"item_{payroll.PayrollID}"
            }
        }
            };

            using var httpClient = new HttpClient();
            httpClient.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", accessToken);

            var response = await httpClient.PostAsJsonAsync("https://api.sandbox.paypal.com/v1/payments/payouts", payoutRequest);

            if (response.IsSuccessStatusCode)
            {
                // Update payroll status to processed
                payroll.PayrollStatus = "Processed";
                _context.Update(payroll);
                await _context.SaveChangesAsync();

                await _emailService.SendPayrollEmailAsync(payroll.Employee.Email, payroll.Employee.FirstName, payroll.NetSalary);
                TempData["Message"] = "Reimbursement successfully processed.";
            }
            else
            {
                var error = await response.Content.ReadAsStringAsync();
                TempData["ErrorMessage"] = $"Failed to reimburse payroll. Error: {error}";
            }

            var userID = HttpContext.Session.GetInt32("UserID");
            await LogAudit(userID ?? 0, $"Reimbursed payroll for {payroll.Employee.FirstName} {payroll.Employee.LastName}");

            return RedirectToAction("Index");
        }

        private async Task<string> GetPayPalAccessTokenAsync()
        {
            var clientId = _configuration["Paypal:ClientId"];
            var secret = _configuration["Paypal:Secret"];

            var byteArray = Encoding.ASCII.GetBytes($"{clientId}:{secret}");
            var httpClient = new HttpClient();

            httpClient.DefaultRequestHeaders.Authorization =
                new AuthenticationHeaderValue("Basic", Convert.ToBase64String(byteArray));

            var postData = new FormUrlEncodedContent(new[]
            {
                new KeyValuePair<string, string>("grant_type", "client_credentials")
            });

            var response = await httpClient.PostAsync("https://api.sandbox.paypal.com/v1/oauth2/token", postData);
            var json = await response.Content.ReadAsStringAsync();

            var token = JsonSerializer.Deserialize<JsonElement>(json)
                .GetProperty("access_token").GetString();

            return token;
        }

        [HttpGet]
        public async Task<IActionResult> DownloadPayslip(int id)
        {
            var payroll = await _context.Payrolls
                .Include(p => p.Employee)
                .Include(p => p.SalaryGrade)
                .FirstOrDefaultAsync(p => p.PayrollID == id);

            if (payroll == null)
            {
                TempData["ErrorMessage"] = "Payroll not found.";
                return RedirectToAction("Index");
            }

            using (MemoryStream ms = new MemoryStream())
            {
                using (Document document = new Document(iTextSharp.text.PageSize.A4, 25, 25, 30, 30))
                {
                    PdfWriter writer = PdfWriter.GetInstance(document, ms);
                    document.Open();

                    // Fonts
                    var headerFont = FontFactory.GetFont(FontFactory.HELVETICA_BOLD, 20, new BaseColor(64, 64, 64));
                    var titleFont = FontFactory.GetFont(FontFactory.HELVETICA_BOLD, 14, new BaseColor(64, 64, 64));
                    var normalFont = FontFactory.GetFont(FontFactory.HELVETICA, 12);
                    var boldFont = FontFactory.GetFont(FontFactory.HELVETICA_BOLD, 12);
                    var amountFont = FontFactory.GetFont(FontFactory.HELVETICA, 12, new BaseColor(0, 0, 139));

                    // Header
                    var header = new Paragraph("PAYSLIP", headerFont);
                    header.Alignment = Element.ALIGN_CENTER;
                    header.SpacingAfter = 20f;
                    document.Add(header);

                    // Company Info
                    var companyInfo = new Paragraph("HR Payroll System", FontFactory.GetFont(FontFactory.HELVETICA_BOLD, 14));
                    companyInfo.Alignment = Element.ALIGN_CENTER;
                    companyInfo.SpacingAfter = 20f;
                    document.Add(companyInfo);

                    // Employee Information Table
                    PdfPTable employeeTable = new PdfPTable(2);
                    employeeTable.WidthPercentage = 100;
                    employeeTable.SpacingBefore = 20f;
                    employeeTable.SpacingAfter = 20f;

                    // Add employee info cells
                    AddCell(employeeTable, "Employee Name:", boldFont);
                    AddCell(employeeTable, $"{payroll.Employee?.FirstName} {payroll.Employee?.LastName}", normalFont);
                    AddCell(employeeTable, "Pay Period:", boldFont);
                    AddCell(employeeTable, payroll.PayPeriod?.ToString("MMMM yyyy"), normalFont);
                    AddCell(employeeTable, "Status:", boldFont);
                    AddCell(employeeTable, payroll.PayrollStatus, normalFont);

                    document.Add(employeeTable);

                    // Earnings Table
                    document.Add(new Paragraph("EARNINGS", titleFont));
                    document.Add(new Paragraph(" ")); // Spacing

                    PdfPTable earningsTable = new PdfPTable(2);
                    earningsTable.WidthPercentage = 100;
                    earningsTable.SpacingBefore = 10f;
                    earningsTable.SpacingAfter = 20f;

                    AddCell(earningsTable, "Basic Salary", normalFont);
                    AddCell(earningsTable, $"₱{payroll.SalaryGrade?.BasicSalary:N2}", amountFont);
                    AddCell(earningsTable, "Allowances", normalFont);
                    AddCell(earningsTable, $"₱{payroll.SalaryGrade?.Allowances:N2}", amountFont);
                    AddCell(earningsTable, "Gross Salary", boldFont);
                    AddCell(earningsTable, $"₱{payroll.GrossSalary:N2}", boldFont);

                    document.Add(earningsTable);

                    // Deductions Table
                    document.Add(new Paragraph("DEDUCTIONS", titleFont));
                    document.Add(new Paragraph(" ")); // Spacing

                    PdfPTable deductionsTable = new PdfPTable(2);
                    deductionsTable.WidthPercentage = 100;
                    deductionsTable.SpacingBefore = 10f;
                    deductionsTable.SpacingAfter = 20f;

                    AddCell(deductionsTable, "SSS", normalFont);
                    AddCell(deductionsTable, $"₱{payroll.Deductions_SSS:N2}", amountFont);
                    AddCell(deductionsTable, "PhilHealth", normalFont);
                    AddCell(deductionsTable, $"₱{payroll.Deductions_PhilHealth:N2}", amountFont);
                    AddCell(deductionsTable, "Pag-IBIG", normalFont);
                    AddCell(deductionsTable, $"₱{payroll.Deductions_PagIbig:N2}", amountFont);
                    AddCell(deductionsTable, "Absences", normalFont);
                    AddCell(deductionsTable, $"₱{payroll.Absences:N2}", amountFont);
                    AddCell(deductionsTable, "Tax", normalFont);
                    AddCell(deductionsTable, $"₱{payroll.TaxWithHolding:N2}", amountFont);
                    AddCell(deductionsTable, "Total Deductions", boldFont);
                    AddCell(deductionsTable, $"₱{(payroll.Deductions_SSS + payroll.Deductions_PhilHealth + payroll.Deductions_PagIbig + payroll.Absences + payroll.TaxWithHolding):N2}", boldFont);

                    document.Add(deductionsTable);

                    // Net Salary
                    PdfPTable netTable = new PdfPTable(2);
                    netTable.WidthPercentage = 100;
                    netTable.SpacingBefore = 20f;
                    netTable.SpacingAfter = 20f;

                    AddCell(netTable, "NET SALARY", titleFont);
                    AddCell(netTable, $"₱{payroll.NetSalary:N2}", FontFactory.GetFont(FontFactory.HELVETICA_BOLD, 14, new BaseColor(0, 0, 139)));

                    document.Add(netTable);

                    // Footer
                    var footer = new Paragraph($"Generated on {DateTime.Now:MMMM dd, yyyy}", FontFactory.GetFont(FontFactory.HELVETICA, 10, new BaseColor(128, 128, 128)));
                    footer.Alignment = Element.ALIGN_CENTER;
                    footer.SpacingBefore = 30f;
                    document.Add(footer);

                    document.Close();
                }

                return File(ms.ToArray(), "application/pdf", $"Payslip_{payroll.Employee?.LastName}_{payroll.PayPeriod?.ToString("MMMM_yyyy")}.pdf");
            }

            var userID = HttpContext.Session.GetInt32("UserID");
            await LogAudit(userID ?? 0, $"Downloaded payslip for {payroll.Employee?.FirstName} {payroll.Employee?.LastName}");
        }

        private void AddCell(PdfPTable table, string text, Font font)
        {
            var cell = new PdfPCell(new Phrase(text, font));
            cell.Padding = 5f;
            cell.Border = Rectangle.NO_BORDER;
            table.AddCell(cell);
        }

        [HttpPost]
        public async Task<IActionResult> SendPayslipEmail(int id)
        {
            var payroll = await _context.Payrolls
                .Include(p => p.Employee)
                .Include(p => p.SalaryGrade)
                .FirstOrDefaultAsync(p => p.PayrollID == id);

            if (payroll == null || payroll.Employee == null)
            {
                TempData["ErrorMessage"] = "Payroll or employee information not found.";
                return RedirectToAction("Index");
            }

            try
            {
                // Generate PDF
                byte[] pdfBytes;
                using (MemoryStream ms = new MemoryStream())
                {
                    using (Document document = new Document(iTextSharp.text.PageSize.A4, 25, 25, 30, 30))
                    {
                        PdfWriter writer = PdfWriter.GetInstance(document, ms);
                        document.Open();

                        // Add the same PDF content as in DownloadPayslip
                        var headerFont = FontFactory.GetFont(FontFactory.HELVETICA_BOLD, 18);
                        var titleFont = FontFactory.GetFont(FontFactory.HELVETICA_BOLD, 14);
                        var normalFont = FontFactory.GetFont(FontFactory.HELVETICA, 12);

                        var header = new Paragraph("PAYSLIP", headerFont);
                        header.Alignment = Element.ALIGN_CENTER;
                        document.Add(header);
                        document.Add(new Paragraph("\n"));

                        document.Add(new Paragraph($"Employee: {payroll.Employee?.FirstName} {payroll.Employee?.LastName}", normalFont));
                        document.Add(new Paragraph($"Pay Period: {payroll.PayPeriod?.ToString("MMMM yyyy")}", normalFont));
                        document.Add(new Paragraph("\n"));

                        document.Add(new Paragraph("EARNINGS", titleFont));
                        document.Add(new Paragraph($"Basic Salary: ₱{payroll.SalaryGrade?.BasicSalary:N2}", normalFont));
                        document.Add(new Paragraph($"Allowances: ₱{payroll.SalaryGrade?.Allowances:N2}", normalFont));
                        document.Add(new Paragraph($"Gross Salary: ₱{payroll.GrossSalary:N2}", normalFont));
                        document.Add(new Paragraph("\n"));

                        document.Add(new Paragraph("DEDUCTIONS", titleFont));
                        document.Add(new Paragraph($"SSS: ₱{payroll.Deductions_SSS:N2}", normalFont));
                        document.Add(new Paragraph($"PhilHealth: ₱{payroll.Deductions_PhilHealth:N2}", normalFont));
                        document.Add(new Paragraph($"Pag-IBIG: ₱{payroll.Deductions_PagIbig:N2}", normalFont));
                        document.Add(new Paragraph($"Absences: ₱{payroll.Absences:N2}", normalFont));
                        document.Add(new Paragraph($"Tax: ₱{payroll.TaxWithHolding:N2}", normalFont));
                        document.Add(new Paragraph($"Total Deductions: ₱{(payroll.Deductions_SSS + payroll.Deductions_PhilHealth + payroll.Deductions_PagIbig + payroll.Absences + payroll.TaxWithHolding):N2}", normalFont));
                        document.Add(new Paragraph("\n"));

                        document.Add(new Paragraph("NET SALARY", titleFont));
                        document.Add(new Paragraph($"₱{payroll.NetSalary:N2}", normalFont));

                        document.Close();
                    }
                    pdfBytes = ms.ToArray();
                }

                // Compose email
                string subject = $"Your Payslip for {payroll.PayPeriod?.ToString("MMMM yyyy")}";
                string message = $@"
                    <p>Dear {payroll.Employee.FirstName},</p>
                    <p>Please find attached your payslip for {payroll.PayPeriod?.ToString("MMMM yyyy")}.</p>
                    <p>If you have any questions, please contact the HR department.</p>
                    <p>Best regards,<br>HR Department</p>";

                // Send email with attachment
                await _emailService.SendEmailAsync(
                    payroll.Employee.Email,
                    subject,
                    message
                );

                TempData["Message"] = "Payslip has been sent to the employee's email.";
            }
            catch (Exception ex)
            {
                TempData["ErrorMessage"] = $"Error sending email: {ex.Message}";
            }

            var userID = HttpContext.Session.GetInt32("UserID");
            await LogAudit(userID ?? 0, $"Sent payslip to {payroll.Employee.Email}");

            return RedirectToAction("Payslip", new { id = id });
        }

        [Authorize(Roles = "HR, Employee, Admin, PayrollStaff")]
        [HttpGet]
        public async Task<IActionResult> ExportPayrollPdf(string searchString = "", string statusFilter = "", int? monthFilter = null, int? yearFilter = null)
        {
            if (!IsUserAuthenticated())
            {
                return RedirectToLogin();
            }

            var payrollQuery = _context.Payrolls
                .Include(p => p.Employee)
                .Include(p => p.SalaryGrade)
                .AsQueryable();

            if (!string.IsNullOrEmpty(searchString))
            {
                payrollQuery = payrollQuery.Where(p =>
                    (p.Employee.FirstName + " " + p.Employee.LastName).Contains(searchString));
            }

            if (!string.IsNullOrEmpty(statusFilter))
            {
                payrollQuery = payrollQuery.Where(p => p.PayrollStatus == statusFilter);
            }

            if (monthFilter.HasValue)
            {
                payrollQuery = payrollQuery.Where(p => p.PayPeriod.Value.Month == monthFilter.Value);
            }

            if (yearFilter.HasValue)
            {
                payrollQuery = payrollQuery.Where(p => p.PayPeriod.Value.Year == yearFilter.Value);
            }

            var payrolls = await payrollQuery.OrderByDescending(p => p.PayPeriod).ToListAsync();

            using (var ms = new MemoryStream())
            {
                var doc = new iTextSharp.text.Document(iTextSharp.text.PageSize.A4.Rotate(), 25, 25, 30, 30);
                var writer = iTextSharp.text.pdf.PdfWriter.GetInstance(doc, ms);
                doc.Open();

                var titleFont = iTextSharp.text.FontFactory.GetFont(iTextSharp.text.FontFactory.HELVETICA_BOLD, 16);
                var headerFont = iTextSharp.text.FontFactory.GetFont(iTextSharp.text.FontFactory.HELVETICA_BOLD, 10);
                var normalFont = iTextSharp.text.FontFactory.GetFont(iTextSharp.text.FontFactory.HELVETICA, 9);

                doc.Add(new iTextSharp.text.Paragraph("Payroll Report", titleFont));
                doc.Add(new iTextSharp.text.Paragraph($"Generated: {DateTime.Now:MMMM dd, yyyy}", normalFont));
                doc.Add(new iTextSharp.text.Paragraph(" "));

                var table = new iTextSharp.text.pdf.PdfPTable(7) { WidthPercentage = 100 };
                table.AddCell(new iTextSharp.text.Phrase("Employee", headerFont));
                table.AddCell(new iTextSharp.text.Phrase("Pay Period", headerFont));
                table.AddCell(new iTextSharp.text.Phrase("Basic Salary", headerFont));
                table.AddCell(new iTextSharp.text.Phrase("Allowance", headerFont));
                table.AddCell(new iTextSharp.text.Phrase("Deductions", headerFont));
                table.AddCell(new iTextSharp.text.Phrase("Net Pay", headerFont));
                table.AddCell(new iTextSharp.text.Phrase("Status", headerFont));

                foreach (var p in payrolls)
                {
                    table.AddCell(new iTextSharp.text.Phrase($"{p.Employee?.FirstName} {p.Employee?.LastName}", normalFont));
                    table.AddCell(new iTextSharp.text.Phrase(p.PayPeriod?.ToString("MMMM yyyy") ?? "", normalFont));
                    table.AddCell(new iTextSharp.text.Phrase($"₱{p.SalaryGrade?.BasicSalary:N2}", normalFont));
                    table.AddCell(new iTextSharp.text.Phrase($"₱{p.SalaryGrade?.Allowances:N2}", normalFont));
                    var deductions = (p.Deductions_SSS ?? 0) + (p.Deductions_PhilHealth ?? 0) + (p.Deductions_PagIbig ?? 0) + (p.Absences ?? 0) + (p.TaxWithHolding ?? 0);
                    table.AddCell(new iTextSharp.text.Phrase($"₱{deductions:N2}", normalFont));
                    table.AddCell(new iTextSharp.text.Phrase($"₱{p.NetSalary:N2}", normalFont));
                    table.AddCell(new iTextSharp.text.Phrase(p.PayrollStatus == "Processed" ? "Processed" : "Pending", normalFont));
                }

                doc.Add(table);
                doc.Close();

                var userID = HttpContext.Session.GetInt32("UserID");
                await LogAudit(userID ?? 0, $"Exported payroll report");

                return File(ms.ToArray(), "application/pdf", $"PayrollReport_{DateTime.Now:yyyyMMdd}.pdf");
            }
        }

    }



    [Authorize(Roles = "HR, Admin, Employee, PayrollStaff")]
    public class AttendanceController : BaseController
    {
        private readonly AuditLogService _audit;            
        public AttendanceController(AppDbContext context, AuditLogService audit) : base(context) {
            _audit = audit;
        }

        public async Task<IActionResult> Myattendance(DateTime? startDate, DateTime? endDate, string status = "", int page = 1)
        {
            if (!IsUserAuthenticated())
            {
                return RedirectToLogin();
            }

            var employeeId = HttpContext.Session.GetInt32("EmployeeID");
            if (!employeeId.HasValue)
            {
                return Unauthorized(); // or redirect to login
            }

            var attendanceQuery = _context.Attendances
                .Include(a => a.Employee)
                .Where(a => a.EmployeeID == employeeId.Value);

            // Apply filters
            if (startDate.HasValue)
                attendanceQuery = attendanceQuery.Where(a => a.Date >= startDate.Value);

            if (endDate.HasValue)
                attendanceQuery = attendanceQuery.Where(a => a.Date <= endDate.Value);

            if (!string.IsNullOrWhiteSpace(status))
            {
                attendanceQuery = attendanceQuery.Where(a => a.AttendanceStatus == status);
            }

            // Pagination
            int pageSize = 10;
            var totalItems = await attendanceQuery.CountAsync();
            var totalPages = (int)Math.Ceiling((double)totalItems / pageSize);

            // Ensure page is within valid range
            page = Math.Max(1, Math.Min(page, totalPages > 0 ? totalPages : 1));

            var attendanceList = await attendanceQuery
                .OrderByDescending(a => a.Date)
                .Skip((page - 1) * pageSize)
                .Take(pageSize)
                .ToListAsync();

            ViewBag.CurrentPage = page;
            ViewBag.TotalPages = totalPages > 0 ? totalPages : 1;
            ViewBag.StartDate = startDate?.ToString("yyyy-MM-dd");
            ViewBag.EndDate = endDate?.ToString("yyyy-MM-dd");
            ViewBag.SelectedStatus = status;

            return View(attendanceList);
        }


        public IActionResult ViewOffice()
        {
            var officeList = _context.Office
                .Select(o => new OfficeMapViewModel
                {
                    OfficeID = o.OfficeID,
                    Name = o.Name,
                    Address = o.Address,
                    Latitude = o.Latitude,
                    Longitude = o.Longitude,
                    GeoFence = o.GeoFence
                })
                .ToList();

            return View(officeList);

        }




        [Authorize(Roles = "HR, Admin")]
        public IActionResult Create( )
        {
           
            return View();
        }
     
     
        [Authorize(Roles = "HR, Admin")]
        [HttpPost]
        public async Task<IActionResult> Create(Office office)
        {
            if (ModelState.IsValid)
            {
                _context.Office.Add(office);
                await _context.SaveChangesAsync();
                var userID = HttpContext.Session.GetInt32("UserID");
                await LogAudit(userID ?? 0, $"Created new office: {office.Name}");

                TempData["Success"] = "Office and geofence saved successfully!";
                return RedirectToAction("Create");
            }

            TempData["Error"] = "Please check the form fields.";
            return View("Create", office);
        }

        [Authorize(Roles = "HR, Admin, PayrollStaff")]
        public async Task<IActionResult> Index(
            int page = 1, 
            int pageSize = 10,
            DateTime? startDate = null,
            DateTime? endDate = null,
            int? department = null,
            string? status = null,
            string? searchString = null)
        {
            if (!IsUserAuthenticated())
            {
                return RedirectToLogin();
            }

            try
            {
                var query = _context.Attendances
                    .Include(a => a.Employee)
                        .ThenInclude(e => e.Department)
                    .AsQueryable();

                // Apply date filters
                if (startDate.HasValue)
                    query = query.Where(a => a.Date >= startDate.Value);
                if (endDate.HasValue)
                    query = query.Where(a => a.Date <= endDate.Value);

                // Apply department filter
                if (department.HasValue)
                    query = query.Where(a => a.Employee.DepartmentID == department.Value);

                // Apply status filter
                if (!string.IsNullOrEmpty(status))
                    query = query.Where(a => a.AttendanceStatus == status);

                // Apply search string
                if (!string.IsNullOrEmpty(searchString))
                {
                    query = query.Where(a => 
                        a.Employee.FirstName.Contains(searchString) ||
                        a.Employee.LastName.Contains(searchString) ||
                        a.Employee.EmployeeID.ToString().Contains(searchString));
                }

                var totalRecords = await query.CountAsync();
                var totalPages = (int)Math.Ceiling(totalRecords / (double)pageSize);

                var attendance = await query
                    .OrderByDescending(a => a.Date)
                    .ThenByDescending(a => a.CheckInTime)
                    .Skip((page - 1) * pageSize)
                    .Take(pageSize)
                    .ToListAsync();

                // Set ViewBag properties for the filters
                ViewBag.StartDate = startDate?.ToString("yyyy-MM-dd");
                ViewBag.EndDate = endDate?.ToString("yyyy-MM-dd");
                ViewBag.SelectedDepartment = department;
                ViewBag.SelectedStatus = status;
                ViewBag.SearchString = searchString;
                ViewBag.Departments = await _context.Departments.ToListAsync();
                ViewBag.CurrentPage = page;
                ViewBag.TotalPages = totalPages;

                return View(attendance);
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
                throw;
            }
        }


        [Authorize(Roles = "HR, Admin, PayrollStaff")]
        public async Task<IActionResult> Report(
            int page = 1, 
            int pageSize = 10,
            DateTime? startDate = null,
            DateTime? endDate = null,
            int? department = null,
            string? searchString = null)
        {
            if (!IsUserAuthenticated())
            {
                return RedirectToLogin();
            }

            try
            {
                var query = _context.Attendances
                    .Include(a => a.Employee)
                        .ThenInclude(e => e.Department)
                    .AsQueryable();

                // Apply date filters
                if (startDate.HasValue)
                    query = query.Where(a => a.Date >= startDate.Value);
                if (endDate.HasValue)
                    query = query.Where(a => a.Date <= endDate.Value);

                // Apply department filter
                if (department.HasValue)
                    query = query.Where(a => a.Employee.DepartmentID == department.Value);

                // Apply search string
                if (!string.IsNullOrEmpty(searchString))
                {
                    query = query.Where(a => 
                        a.Employee.FirstName.Contains(searchString) ||
                        a.Employee.LastName.Contains(searchString) ||
                        a.Employee.EmployeeID.ToString().Contains(searchString));
                }

                var totalRecords = await query.CountAsync();
                var totalPages = (int)Math.Ceiling(totalRecords / (double)pageSize);

                var attendancereport = await query
                    .OrderByDescending(a => a.Date)
                    .ThenByDescending(a => a.CheckInTime)
                    .Skip((page - 1) * pageSize)
                    .Take(pageSize)
                    .ToListAsync();

                // Set ViewBag properties for the filters
                ViewBag.StartDate = startDate?.ToString("yyyy-MM-dd");
                ViewBag.EndDate = endDate?.ToString("yyyy-MM-dd");
                ViewBag.SelectedDepartment = department;
                ViewBag.SearchString = searchString;
                ViewBag.Departments = await _context.Departments.ToListAsync();
                ViewBag.CurrentPage = page;
                ViewBag.TotalPages = totalPages;

                return View(attendancereport);
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
                throw;
            }
        }


        [Authorize(Roles = "HR, Admin,")]
        [HttpGet]
        public async Task<IActionResult> DownloadCsv()
        {
            if (!IsUserAuthenticated())
            {
                return RedirectToLogin();
            }

            var attendances = await _context.Attendances.Include(a => a.Employee).ToListAsync();

            var csv = new StringBuilder();
            csv.AppendLine("Name,Date,CheckIn,CheckOut,TotalHours,Status");

            foreach (var a in attendances)
            {
                var name = $"{a.Employee?.FirstName} {a.Employee?.LastName}";
                var date = a.Date?.ToString("yyyy-MM-dd") ?? "—";
                var checkIn = a.CheckInTime.HasValue ? DateTime.Today.Add(a.CheckInTime.Value).ToString("h:mm tt") : "—";
                var checkOut = a.CheckOutTime.HasValue ? DateTime.Today.Add(a.CheckOutTime.Value).ToString("h:mm tt") : "—";
                var total = a.TotalHoursWorked.HasValue
                    ? $"{(int)(a.TotalHoursWorked * 60) / 60}h {(int)(a.TotalHoursWorked * 60) % 60}m"
                    : "—";
                var status = a.AttendanceStatus ?? "—";

                csv.AppendLine($"{name},{date},{checkIn},{checkOut},{total},{status}");
            }

            var bytes = Encoding.UTF8.GetBytes(csv.ToString());

            // Set "read-only" Content-Disposition for download
            Response.Headers["Content-Disposition"] = "attachment; filename=AttendanceReport.csv";

            var userID = HttpContext.Session.GetInt32("UserID");
            await LogAudit(userID ?? 0, $"Downloaded attendance report");

            return File(bytes, "text/csv");
        }







        public async Task<IActionResult> PunchIn(DateTime date, double latitude, double longitude)
        {
            if (!IsUserAuthenticated())
            {
                return RedirectToLogin();
            }

            var empID = HttpContext.Session.GetInt32("EmployeeID");
            if (empID == null)
            {
                TempData["Error"] = "Invalid employee session.";
                return RedirectToAction("Index", "Dashboard");
            }

            // Convert UTC to local time (Asia/Manila timezone)
            var utcNow = DateTime.UtcNow;
            var philippineTime = TimeZoneInfo.ConvertTimeFromUtc(utcNow, TimeZoneInfo.FindSystemTimeZoneById("Asia/Manila"));
            var today = philippineTime.Date;

            var existingAttendance = await _context.Attendances
                .FirstOrDefaultAsync(a => a.EmployeeID == empID && a.Date == today);

            if (existingAttendance != null)
            {
                TempData["Error"] = "You have already punched in for today!";
                return RedirectToAction("Index", "Dashboard");  
            }

            // Load default office by ID (e.g., OfficeID = 1)
            var office = await _context.Office.FirstOrDefaultAsync(o => o.OfficeID > 0);
            string geoJsonPolygon = office?.GeoFence; // Check if this is not null
            Console.WriteLine(geoJsonPolygon);

            if (office == null)
            {
                TempData["Error"] = "Office location not configured.";
                return RedirectToAction("Index", "Dashboard");
            }

            Console.WriteLine($"[DEBUG] User: {latitude},{longitude} | Office: {office.Latitude},{office.Longitude}");
            if (latitude == 0 || longitude == 0 || office.Latitude == 0 || office.Longitude == 0)
            {
                TempData["Error"] = "Invalid coordinates detected.";
                return RedirectToAction("Index", "Dashboard");
            }

            // Check if employee is inside the geofenced polygon
            bool insideGeofence = IsInsideGeofence(latitude, longitude, office.GeoFence);

            if (!insideGeofence)
            {
                TempData["Error"] = "You are outside the allowed punch-in geofence area.";
                return RedirectToAction("Index", "Dashboard");
            }

            // Check if employee is late (after 8:15 AM) using Philippine time
            var defaultWorkTime = new DateTime(philippineTime.Year, philippineTime.Month, philippineTime.Day, 8, 15, 0);
            string attendanceStatus = philippineTime > defaultWorkTime ? "Late" : "Present";

            var attendance = new Attendance
            {
                EmployeeID = empID.Value,
                Date = today,
                CheckInTime = TimeSpan.FromSeconds(philippineTime.TimeOfDay.TotalSeconds),
                CheckOutTime = TimeSpan.Zero,
                AttendanceStatus = attendanceStatus,
                TotalHoursWorked = 0,
                OvertimeHours = 0
            };

            _context.Attendances.Add(attendance);
            await _context.SaveChangesAsync();

            TempData["Success"] = "Punched in successfully!";
            return RedirectToAction("Index", "Dashboard");
        }

        private bool IsInsideGeofence(double latitude, double longitude, string geoJsonPolygon)
        {
            // Parse the GeoJSON string into a polygon
            var reader = new GeoJsonReader();
            Polygon polygon = reader.Read<Polygon>(geoJsonPolygon);

            // Create a point based on the user's location
            var point = new Point(longitude, latitude); // X = Longitude, Y = Latitude

            // Debugging information to check if coordinates and GeoJSON are correct
            Console.WriteLine($"GeoJSON Polygon: {geoJsonPolygon}");
            Console.WriteLine($"Point: ({latitude}, {longitude})");

            // Check if the point is inside the polygon
            bool isInside = polygon.Covers(point); // Use Contains to strictly check inside the polygon
            Console.WriteLine($"Inside Geofence? {isInside}");

            return isInside;
        }




        private double CalculateDistance(double lat1, double lon1, double lat2, double lon2)
        {
            const double R = 6371000;

            // Convert degrees to radians
            var phi1 = lat1 * Math.PI / 180;
            var phi2 = lat2 * Math.PI / 180;
            var deltaPhi = (lat2 - lat1) * Math.PI / 180;
            var deltaLambda = (lon2 - lon1) * Math.PI / 180;

            var a = Math.Sin(deltaPhi / 2) * Math.Sin(deltaPhi / 2) +
                    Math.Cos(phi1) * Math.Cos(phi2) *
                    Math.Sin(deltaLambda / 2) * Math.Sin(deltaLambda / 2);

            var c = 2 * Math.Atan2(Math.Sqrt(a), Math.Sqrt(1 - a));

            return R * c;
        }



        [HttpPost]
        public async Task<IActionResult> PunchOut()
        {
            if (!IsUserAuthenticated())
            {
                return RedirectToLogin();
            }

            var employeeId = HttpContext.Session.GetInt32("EmployeeID");
            if (employeeId == null)
            {
                TempData["Error"] = "Invalid employee session.";
                return RedirectToAction("Index", "Dashboard");
            }

            // Convert UTC to local time (Asia/Manila timezone)
            var utcNow = DateTime.UtcNow;
            var philippineTime = TimeZoneInfo.ConvertTimeFromUtc(utcNow, TimeZoneInfo.FindSystemTimeZoneById("Asia/Manila"));
            var today = philippineTime.Date;

            // Find today's attendance
            var attendance = await _context.Attendances
                .FirstOrDefaultAsync(a => a.EmployeeID == employeeId && a.Date == today);

            if (attendance == null)
            {
                TempData["Error"] = "No punch-in record found for today!";
                return RedirectToAction("Index", "Dashboard");
            }

            // Update CheckOutTime using Philippine time
            attendance.CheckOutTime = TimeSpan.FromSeconds(philippineTime.TimeOfDay.TotalSeconds);

            if (attendance.CheckInTime.HasValue)
            {
                // Compute total hours worked
                var totalHours = attendance.CheckOutTime.Value - attendance.CheckInTime.Value;
                attendance.TotalHoursWorked = (decimal?)totalHours.TotalHours;

                // Compute overtime (beyond 8 hours)
                var overtime = attendance.TotalHoursWorked - 8;
                attendance.OvertimeHours = overtime > 0 ? (decimal?)overtime : 0;
            }

            await _context.SaveChangesAsync();

            TempData["Success"] = "Punched out successfully!";
            return RedirectToAction("Index", "Dashboard");
        }


        [Authorize(Roles = "HR, Admin")]
        public async Task<IActionResult> AttendanceStatus()
        {
            if (!IsUserAuthenticated())
            {
                return RedirectToLogin();
            }

            var employeeId = HttpContext.Session.GetInt32("EmployeeID");
            var today = DateTime.Today;

            var attendance = await _context.Attendances
                .FirstOrDefaultAsync(a => a.EmployeeID == employeeId && a.Date == today);

            var result = new
            {
                IsPunchedIn = attendance != null && attendance.CheckInTime != null,
                IsPunchedOut = attendance != null && attendance.CheckOutTime != TimeSpan.Zero
            };

            return Json(result);
        }

        // Add this new method
        public async Task<IActionResult> MarkAbsentEmployees()
        {
            if (!IsUserAuthenticated())
            {
                return RedirectToLogin();
            }

            try
            {
                var today = DateTime.Today;
                
                // Get all active employees
                var activeEmployees = await _context.Employees
                    .Where(e => e.EmploymentStatus == "Active")
                    .ToListAsync();

                // Get all attendance records for today
                var todayAttendance = await _context.Attendances
                    .Where(a => a.Date == today)
                    .Select(a => a.EmployeeID)
                    .ToListAsync();

                // Find employees who haven't checked in today
                var absentEmployees = activeEmployees
                    .Where(e => !todayAttendance.Contains(e.EmployeeID))
                    .ToList();

                // Create attendance records for absent employees
                foreach (var employee in absentEmployees)
                {
                    var attendance = new Attendance
                    {
                        EmployeeID = employee.EmployeeID,
                        Date = today,
                        CheckInTime = null,
                        CheckOutTime = null,
                        AttendanceStatus = "Absent",
                        TotalHoursWorked = 0,
                        OvertimeHours = 0
                    };

                    _context.Attendances.Add(attendance);
                }

                await _context.SaveChangesAsync();
                return Json(new { success = true, message = $"Marked {absentEmployees.Count} employees as absent." });
            }
            catch (Exception ex)
            {
                return Json(new { success = false, message = $"Error marking absent employees: {ex.Message}" });
            }
        }

        [Authorize(Roles = "HR, Admin, PayrollStaff")]
        [HttpGet]
        public async Task<IActionResult> DownloadPdf(DateTime? startDate = null, DateTime? endDate = null, int? department = null, string? searchString = null)
        {
            if (!IsUserAuthenticated())
            {
                return RedirectToLogin();
            }

            var query = _context.Attendances
                .Include(a => a.Employee)
                .AsQueryable();

            if (startDate.HasValue)
                query = query.Where(a => a.Date >= startDate.Value);
            if (endDate.HasValue)
                query = query.Where(a => a.Date <= endDate.Value);
            if (department.HasValue)
                query = query.Where(a => a.Employee.DepartmentID == department.Value);
            if (!string.IsNullOrEmpty(searchString))
            {
                query = query.Where(a =>
                    a.Employee.FirstName.Contains(searchString) ||
                    a.Employee.LastName.Contains(searchString) ||
                    a.Employee.EmployeeID.ToString().Contains(searchString));
            }

            var attendances = await query.OrderBy(a => a.Date).ToListAsync();

            using (var ms = new MemoryStream())
            {
                var doc = new iTextSharp.text.Document(iTextSharp.text.PageSize.A4, 25, 25, 30, 30);
                var writer = iTextSharp.text.pdf.PdfWriter.GetInstance(doc, ms);
                doc.Open();

                var titleFont = iTextSharp.text.FontFactory.GetFont(iTextSharp.text.FontFactory.HELVETICA_BOLD, 16);
                var headerFont = iTextSharp.text.FontFactory.GetFont(iTextSharp.text.FontFactory.HELVETICA_BOLD, 12);
                var normalFont = iTextSharp.text.FontFactory.GetFont(iTextSharp.text.FontFactory.HELVETICA, 10);

                doc.Add(new iTextSharp.text.Paragraph("Attendance Report", titleFont));
                doc.Add(new iTextSharp.text.Paragraph($"Generated: {DateTime.Now:MMMM dd, yyyy}", normalFont));
                doc.Add(new iTextSharp.text.Paragraph(" "));

                var table = new iTextSharp.text.pdf.PdfPTable(6) { WidthPercentage = 100 };
                table.AddCell(new iTextSharp.text.Phrase("Employee", headerFont));
                table.AddCell(new iTextSharp.text.Phrase("Date", headerFont));
                table.AddCell(new iTextSharp.text.Phrase("Check-in", headerFont));
                table.AddCell(new iTextSharp.text.Phrase("Check-out", headerFont));
                table.AddCell(new iTextSharp.text.Phrase("Total Hours", headerFont));
                table.AddCell(new iTextSharp.text.Phrase("Status", headerFont));

                foreach (var a in attendances)
                {
                    table.AddCell(new iTextSharp.text.Phrase($"{a.Employee?.FirstName} {a.Employee?.LastName}", normalFont));
                    table.AddCell(new iTextSharp.text.Phrase(a.Date?.ToString("yyyy-MM-dd") ?? "—", normalFont));
                    table.AddCell(new iTextSharp.text.Phrase(a.CheckInTime.HasValue ? DateTime.Today.Add(a.CheckInTime.Value).ToString("h:mm tt") : "—", normalFont));
                    table.AddCell(new iTextSharp.text.Phrase(a.CheckOutTime.HasValue ? DateTime.Today.Add(a.CheckOutTime.Value).ToString("h:mm tt") : "—", normalFont));
                    if (a.TotalHoursWorked.HasValue)
                    {
                        var totalMinutes = (int)(a.TotalHoursWorked.Value * 60);
                        var hours = totalMinutes / 60;
                        var minutes = totalMinutes % 60;
                        table.AddCell(new iTextSharp.text.Phrase($"{hours}h {minutes}m", normalFont));
                    }
                    else
                    {
                        table.AddCell(new iTextSharp.text.Phrase("—", normalFont));
                    }
                    table.AddCell(new iTextSharp.text.Phrase(a.AttendanceStatus ?? "—", normalFont));
                }

                doc.Add(table);
                doc.Close();

                var userID = HttpContext.Session.GetInt32("UserID");
                await LogAudit(userID ?? 0, $"Downloaded attendance report");

                return File(ms.ToArray(), "application/pdf", $"AttendanceReport_{DateTime.Now:yyyyMMdd}.pdf");
            }
        }

    }


    



    [Authorize(Roles = "HR, Employee, Admin, PayrollStaff")]
    public class LeaveController : BaseController
    {
        private readonly AuditLogService _audit;

        public LeaveController(AppDbContext context, AuditLogService audit) : base(context)
        {
            _audit = audit;
        }

        [Authorize(Roles = "HR, Admin")]
        public async Task<IActionResult> Index(
            int page = 1,
            string status = "",
            string leaveType = "",
            string search = "",
            DateTime? date = null)
        {
            if (!IsUserAuthenticated())
            {
                return RedirectToLogin();
            }

            int pageSize = 10;

            var leaveQuery = _context.Leaves
                .Include(l => l.Employee)
                .AsQueryable();

            // Filter by status
            if (!string.IsNullOrEmpty(status) && status != "All")
                leaveQuery = leaveQuery.Where(l => l.ApprovalStatus == status);

            // Filter by leave type
            if (!string.IsNullOrEmpty(leaveType) && leaveType != "All")
                leaveQuery = leaveQuery.Where(l => l.LeaveType == leaveType);

            // Filter by employee name (search)
            if (!string.IsNullOrEmpty(search))
                leaveQuery = leaveQuery.Where(l =>
                    l.Employee.FirstName.Contains(search) ||
                    l.Employee.LastName.Contains(search));

            // Filter by date (if provided)
            if (date.HasValue)
                leaveQuery = leaveQuery.Where(l => l.StartDate <= date && l.EndDate >= date);

            leaveQuery = leaveQuery.OrderByDescending(l => l.StartDate);

            int totalItems = await leaveQuery.CountAsync();
            int totalPages = (int)Math.Ceiling((double)totalItems / pageSize);
            if (totalPages < 1) totalPages = 1;
            if (page < 1) page = 1;
            if (page > totalPages) page = totalPages;

            var leaveRequests = await leaveQuery
                .Skip((page - 1) * pageSize)
                .Take(pageSize)
                .ToListAsync();

            ViewBag.CurrentPage = page;
            ViewBag.TotalPages = totalPages;
            ViewBag.Status = status;
            ViewBag.LeaveType = leaveType;
            ViewBag.Search = search;
            ViewBag.Date = date?.ToString("yyyy-MM-dd");

            return View(leaveRequests);
        }




        [HttpGet]
        public IActionResult ApplyLeave()
        {
            return View();
        }


        [Authorize(Roles = "HR, Admin")]
        [HttpPost]
        public async Task<IActionResult> Approve(int leaveId)
        {
            if (!IsUserAuthenticated())
            {
                return RedirectToLogin();
            }

            var userID = HttpContext.Session.GetInt32("UserID");
            var employee = HttpContext.Session.GetInt32("EmployeeID");
            var leaveRequest = await _context.Leaves.FindAsync(leaveId);
            if (leaveRequest == null)
            {
                return NotFound();
            }

            leaveRequest.ApprovalStatus = "Approved";
            leaveRequest.HR_ApprovedBy = employee;

            // Log the action
            await LogAudit(userID ?? 0, $"Approved leave request for employee ID: {leaveRequest.EmployeeID} (Leave ID: {leaveRequest.LeaveID})");
          

            _context.Leaves.Update(leaveRequest);
            await _context.SaveChangesAsync();

            return RedirectToAction(nameof(Index));
        }
        // Reject Leave Request

        [Authorize(Roles = "HR, Admin")]
        [HttpPost]
        public async Task<IActionResult> Reject(int leaveId)
        {
            if (!IsUserAuthenticated())
            {
                return RedirectToLogin();
            }

            var userID = HttpContext.Session.GetInt32("UserID");
            var employee = HttpContext.Session.GetInt32("EmployeeID");
            var leaveRequest = await _context.Leaves.FindAsync(leaveId);
            if (leaveRequest == null)
            {
                return NotFound();
            }

            leaveRequest.ApprovalStatus = "Rejected";
            leaveRequest.HR_ApprovedBy = employee;

            await LogAudit(userID ?? 0, $"Rejected leave request for employee ID: {leaveRequest.EmployeeID} (Leave ID: {leaveRequest.LeaveID})");


            _context.Leaves.Update(leaveRequest);
            await _context.SaveChangesAsync();

            return RedirectToAction(nameof(Index));
        }

        // View Leave Request
        [Authorize(Roles = "HR, Admin, Employee, PayrollStaff")]
        public async Task<IActionResult> ViewLeave(int leaveId)
        {
            if (!IsUserAuthenticated())
            {
                return RedirectToLogin();
            }

            var leaveRequest = await _context.Leaves
                .Include(l => l.Employee)  // Include Employee to view details
                .FirstOrDefaultAsync(l => l.LeaveID == leaveId);

            if (leaveRequest == null)
            {
                return NotFound();
            }

            return View(leaveRequest); // You can create a view to show detailed leave info
        }



        // POST: Leave/Apply
        [Authorize(Roles = "HR, Admin, Employee, PayrollStaff")]
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ApplyLeave([Bind("EmployeeID,LeaveType,StartDate,EndDate,Reason,ApprovalStatus,HR_ApprovedBy")] Leave leave)
        {
            if (!IsUserAuthenticated())
            {
                return RedirectToLogin();
            }

            try
            {
                var employeeId = HttpContext.Session.GetInt32("EmployeeID");

                if (employeeId == null)
                {
                    TempData["Error"] = "You are not logged in or session has expired.";
                    return RedirectToAction("Login", "Account");
                }

                // Set fields BEFORE validation
                leave.EmployeeID = employeeId.Value;
                leave.ApprovalStatus = "Pending";
                leave.HR_ApprovedBy = null;

                if (ModelState.IsValid)
                {
                    _context.Add(leave);
                    await _context.SaveChangesAsync();

                    TempData["Success"] = "Leave request submitted successfully.";
                    return RedirectToAction("ApplyLeave");
                }

                var errorMessages = ModelState.Values
                    .SelectMany(v => v.Errors)
                    .Select(e => e.ErrorMessage)
                    .ToList();

                TempData["Error"] = "Form submission failed. Please fix the following error(s): " +
                                    string.Join(" | ", errorMessages);

                return View(leave);
            }
            catch (Exception ex)
            {
                TempData["Error"] = "Unexpected error occurred: " + ex.Message;
                return View(leave);
            }
        }

        // GET: Leave/MyLeaveHistory
        public async Task<IActionResult> Myleave(int page = 1, string status = "", string leaveType = "", DateTime? date = null)
        {
            if (!IsUserAuthenticated())
            {
                return RedirectToLogin();
            }

            var employeeId = HttpContext.Session.GetInt32("EmployeeID");
            if (employeeId == null)
            {
                TempData["Error"] = "You are not logged in or session has expired.";
                return RedirectToAction("Login", "Auth");
            }

            int pageSize = 10;

            var leaveQuery = _context.Leaves
                .Where(l => l.EmployeeID == employeeId)
                .AsQueryable();

            // Filter by status
            if (!string.IsNullOrEmpty(status) && status != "All")
                leaveQuery = leaveQuery.Where(l => l.ApprovalStatus == status);

            // Filter by leave type
            if (!string.IsNullOrEmpty(leaveType) && leaveType != "All")
                leaveQuery = leaveQuery.Where(l => l.LeaveType == leaveType);

            // Filter by date (if provided)
            if (date.HasValue)
                leaveQuery = leaveQuery.Where(l => l.StartDate <= date && l.EndDate >= date);

            leaveQuery = leaveQuery.OrderByDescending(l => l.StartDate);

            int totalItems = await leaveQuery.CountAsync();
            int totalPages = (int)Math.Ceiling((double)totalItems / pageSize);
            if (totalPages < 1) totalPages = 1;
            if (page < 1) page = 1;
            if (page > totalPages) page = totalPages;

            var leaveHistory = await leaveQuery
                .Skip((page - 1) * pageSize)
                .Take(pageSize)
                .ToListAsync();

            ViewBag.CurrentPage = page;
            ViewBag.TotalPages = totalPages;
            ViewBag.Status = status;
            ViewBag.LeaveType = leaveType;
            ViewBag.Date = date?.ToString("yyyy-MM-dd");

            return View(leaveHistory);
        }
    }





    [Authorize(Roles = "HR, Employee, Admin, PayrollStaff")]
    public class SecurityController : BaseController
    {
        private readonly IWebHostEnvironment _webHostEnvironment;
        private readonly AuditLogService _audit;

        public SecurityController(AppDbContext context, IWebHostEnvironment webHostEnvironment, AuditLogService audit) : base(context)
        {
            _webHostEnvironment = webHostEnvironment;
            _audit = audit;
        }

        public IActionResult Profile()
        {
            return View(); 
        }

        [Authorize(Roles = "HR, Admin")]
        public async Task<IActionResult> Roles(int page = 1, int pageSize = 10)
        {
            if (!IsUserAuthenticated())
            {
                return RedirectToLogin();
            }

            var totalUsers = await _context.UserRoles.CountAsync();
            var totalPages = (int)Math.Ceiling(totalUsers / (double)pageSize);

            var users = await _context.UserRoles
                .Include(u => u.Employee)
                .Skip((page - 1) * pageSize)
                .Take(pageSize)
                .ToListAsync();

            ViewBag.Employees = await _context.Employees.ToListAsync();
            ViewBag.CurrentPage = page;
            ViewBag.TotalPages = totalPages;

            return View(users);
        }



        [HttpPost]
        public async Task<IActionResult> UpdateRole(int userId, string newRole)
        {
            if (!IsUserAuthenticated())
            {
                return RedirectToLogin();
            }

            var user = await _context.UserRoles.FindAsync(userId);
            if (user != null)
            {
                user.Role = newRole;
                _context.Update(user);

                await LogAudit(userId, $"Updated Role to '{newRole}' for user '{user.Username}'");
                await _context.SaveChangesAsync();
                var userID = HttpContext.Session.GetInt32("UserID");
                await LogAudit(userID ?? 0, $"Updated Role to '{newRole}' for user '{user.Username}'");
            }
            return RedirectToAction("Roles");
        }

        public string HashPassword(string password)
        {
            byte[] salt = RandomNumberGenerator.GetBytes(16);
            var hash = new Rfc2898DeriveBytes(password, salt, 10000, HashAlgorithmName.SHA256);
            byte[] hashBytes = hash.GetBytes(32);

            byte[] hashWithSalt = new byte[48];
            Buffer.BlockCopy(salt, 0, hashWithSalt, 0, 16);
            Buffer.BlockCopy(hashBytes, 0, hashWithSalt, 16, 32);

            return Convert.ToBase64String(hashWithSalt);
        }




        private new async Task LogAudit(int userId, string action)
        {

            var audit = new AuditLog
            {
                UserID = userId,
                ActionTaken = action,
                Timestamp = DateTime.Now,
                IPAddress = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "Unknown"
            };
            _context.AuditLogs.Add(audit);
            await _context.SaveChangesAsync();
        }

        [Authorize(Roles = "HR, Admin, Employee, PayrollStaff")]
        [HttpPost]
        public async Task<IActionResult> CreateUser(string username, int employeeId, string role, string status)
        {
            if (!IsUserAuthenticated())
            {
                return RedirectToLogin();
            }

            // Check if username already exists
            if (await _context.UserRoles.AnyAsync(u => u.Username == username))
            {
                TempData["Error"] = "Username already exists.";
                return RedirectToAction("Roles");
            }

            var user = new HRPayrollSystem.Models.User
            {
                Username = username,
                EmployeeID = employeeId,
                Role = role,
                Status = status,
                TwoFactorEnabled = false,
                LastLogin = DateTime.Today,
                PasswordHash = HashPassword("123") // Default password
            };


            _context.UserRoles.Add(user);
            await _context.SaveChangesAsync();

            var userID = HttpContext.Session.GetInt32("UserID");
            await LogAudit(userID ?? 0, $"Created new user '{username}' with role '{role}'");

            TempData["Success"] = $"User '{username}' created with default password '123'.";
            return RedirectToAction("Roles");
        }




        [Authorize(Roles = "HR, Admin, Employee, PayrollStaff")]
        [HttpPost]
        public async Task<IActionResult> ToggleTwoFactor(int userId, bool enable)
        {
            if (!IsUserAuthenticated())
            {
                return RedirectToLogin();
            }

            try
            {
                var user = await _context.UserRoles.FindAsync(userId);
                if (user != null)
                {
                    user.TwoFactorEnabled = enable;
                    _context.Update(user);

                    string status = enable ? "Enabled" : "Disabled";
                    await LogAudit(userId, $"{status} 2FA for '{user.Username}'");

                    await _context.SaveChangesAsync();

                    var userID = HttpContext.Session.GetInt32("UserID");
                    await LogAudit(userID ?? 0, $"{status} 2FA for '{user.Username}'"); 

                    TempData["Sucess"] = $"{status} Two-Factor Authentication successfully for user '{user.Username}'.";
                }
                else
                {
                    TempData["Error"] = "User not found.";
                }
            }
            catch (Exception ex)
            {
                TempData["Error"] = "An error occurred while toggling Two-Factor Authentication.";
                // Optional: log exception to file or service
                Console.WriteLine(ex.Message);
            }

            return RedirectToAction("Roles");
        }



        [Authorize(Roles = "HR, Admin, PayrollStaff")]
        public async Task<IActionResult> Auditlogs(int page = 1, int pageSize = 10, DateTime? startDate = null, DateTime? endDate = null, string? userSearch = null)
        {
            if (!IsUserAuthenticated())
            {
                return RedirectToLogin();
            }

            var logsQuery = _context.AuditLogs
                .Include(log => log.User)
                .AsQueryable();

            // Filter by date range
            if (startDate.HasValue)
                logsQuery = logsQuery.Where(l => l.Timestamp >= startDate.Value);
            if (endDate.HasValue)
                logsQuery = logsQuery.Where(l => l.Timestamp <= endDate.Value.AddDays(1).AddTicks(-1));

            // Filter by user name
            if (!string.IsNullOrWhiteSpace(userSearch))
                logsQuery = logsQuery.Where(l => l.User.Username.Contains(userSearch));

            logsQuery = logsQuery.OrderByDescending(log => log.Timestamp);

            var totalLogs = await logsQuery.CountAsync();
            var totalPages = (int)Math.Ceiling(totalLogs / (double)pageSize);

            var logs = await logsQuery
                .Skip((page - 1) * pageSize)
                .Take(pageSize)
                .ToListAsync();

            ViewBag.CurrentPage = page;
            ViewBag.TotalPages = totalPages;
            ViewBag.StartDate = startDate?.ToString("yyyy-MM-dd");
            ViewBag.EndDate = endDate?.ToString("yyyy-MM-dd");
            ViewBag.UserSearch = userSearch;

            return View(logs);
        }


        [Authorize(Roles = "HR, Admin, PayrollStaff")]
        public async Task<IActionResult> Department(int page = 1, int pageSize = 10, string searchString = "")
        {
            if (!IsUserAuthenticated())
            {
                return RedirectToLogin();
            }

            try
            {
                var query = _context.Departments
                    .Include(d => d.Manager)
                    .AsQueryable();

                // Apply search filter if provided
                if (!string.IsNullOrEmpty(searchString))
                {
                    query = query.Where(d => 
                        d.DepartmentName.Contains(searchString) || 
                        (d.Manager != null && 
                         (d.Manager.FirstName.Contains(searchString) || 
                          d.Manager.LastName.Contains(searchString))));
                }

                var totalDepartments = await query.CountAsync();
                var totalPages = (int)Math.Ceiling(totalDepartments / (double)pageSize);

                // Ensure page is within valid range
                page = Math.Max(1, Math.Min(page, totalPages > 0 ? totalPages : 1));

                var departments = await query
                    .OrderBy(d => d.DepartmentName)
                    .Skip((page - 1) * pageSize)
                    .Take(pageSize)
                    .ToListAsync();

                ViewBag.CurrentPage = page;
                ViewBag.TotalPages = totalPages;
                ViewBag.SearchString = searchString;

                return View(departments);
            }
            catch (Exception ex)
            {
                TempData["Error"] = "An error occurred while retrieving departments: " + ex.Message;
                return View(new List<Department>());
            }
        }

        [Authorize(Roles = "HR, Admin, PayrollStaff")]
        public async Task<IActionResult> AddDepartment()
        {
            if (!IsUserAuthenticated())
            {
                return RedirectToLogin();
            }

            // Get list of employees for manager selection
            ViewBag.Managers = await _context.Employees
                .Select(e => new SelectListItem
                {
                    Value = e.EmployeeID.ToString(),
                    Text = $"{e.FirstName} {e.LastName}"
                }).ToListAsync();
                

            return View();
        }

        [Authorize(Roles = "HR, Admin, PayrollStaff")]
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> AddDepartment(Department department)
        {
            if (!IsUserAuthenticated())
            {
                return RedirectToLogin();
            }

            if (ModelState.IsValid)
            {
                try
                {
                    // Check if department name already exists
                    if (await _context.Departments.AnyAsync(d => d.DepartmentName == department.DepartmentName))
                    {
                        TempData["Error"] = "A department with this name already exists.";
                        ViewBag.Managers = await _context.Employees
                            .Select(e => new SelectListItem
                            {
                                Value = e.EmployeeID.ToString(),
                                Text = $"{e.FirstName} {e.LastName}"
                            }).ToListAsync();
                        return View(department);
                    }

                    _context.Departments.Add(department);
                    await _context.SaveChangesAsync();

                    var userID = HttpContext.Session.GetInt32("UserID");
                    await LogAudit(userID ?? 0, $"Created new Department: {department.DepartmentName}");
                    TempData["Success"] = "Department created successfully.";
                    return RedirectToAction("Department");
                }
                catch (Exception ex)
                {
                    TempData["Error"] = "An error occurred while creating the department: " + ex.Message;
                }
            }

            // If we got this far, something failed, redisplay form
            ViewBag.Managers = await _context.Employees
                .Select(e => new SelectListItem
                {
                    Value = e.EmployeeID.ToString(),
                    Text = $"{e.FirstName} {e.LastName}"
                }).ToListAsync();
            return View(department);
        }


        

        [Authorize(Roles = "HR, Admin")]
        [HttpPost]
        public async Task<IActionResult> DeleteDepartment(int id)
        {
            if (!IsUserAuthenticated())
            {
                return RedirectToLogin();
            }

            try
            {
                var department = await _context.Departments.FindAsync(id);
                if (department == null)
                {
                    TempData["Error"] = "Department not found.";
                    return RedirectToAction("Department");
                }

                // Check if department has any employees
                var hasEmployees = await _context.Employees.AnyAsync(e => e.DepartmentID == id);
                if (hasEmployees)
                {
                    TempData["Error"] = "Cannot delete department that has employees assigned to it.";
                    return RedirectToAction("Department");
                }

                _context.Departments.Remove(department);
                await _context.SaveChangesAsync();

                await LogAudit(GetCurrentUserId(), $"Deleted Department: {department.DepartmentName}");

                TempData["Success"] = "Department deleted successfully.";
            }
            catch (Exception ex)
            {
                TempData["Error"] = "An error occurred while deleting the department: " + ex.Message;
            }

            return RedirectToAction("Department");
        }

        [Authorize(Roles = "HR, Admin")]
        public async Task<IActionResult> EditDepartment(int id)
        {
            if (!IsUserAuthenticated())
            {
                return RedirectToLogin();
            }

            var department = await _context.Departments.FindAsync(id);
            if (department == null)
            {
                TempData["Error"] = "Department not found.";
                return RedirectToAction("Department");
            }

            ViewBag.Managers = await _context.Employees
                .Select(e => new SelectListItem
                {
                    Value = e.EmployeeID.ToString(),
                    Text = $"{e.FirstName} {e.LastName}"
                }).ToListAsync();

            return View(department);
        }

        [Authorize(Roles = "HR, Admin")]
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> EditDepartment(Department department)
        {
            if (!IsUserAuthenticated())
            {
                return RedirectToLogin();
            }

            if (ModelState.IsValid)
            {
                try
                {
                    // Check if department name already exists (excluding current department)
                    if (await _context.Departments.AnyAsync(d => 
                        d.DepartmentName == department.DepartmentName && 
                        d.DepartmentID != department.DepartmentID))
                    {
                        TempData["Error"] = "A department with this name already exists.";
                        ViewBag.Managers = await _context.Employees
                            .Select(e => new SelectListItem
                            {
                                Value = e.EmployeeID.ToString(),
                                Text = $"{e.FirstName} {e.LastName}"
                            }).ToListAsync();
                        return View(department);
                    }

                    _context.Update(department);
                    await _context.SaveChangesAsync();

                    await LogAudit(GetCurrentUserId(), $"Updated Department: {department.DepartmentName}");
                    TempData["Success"] = "Department updated successfully.";
                    return RedirectToAction("Department");
                }
                catch (Exception ex)
                {
                    TempData["Error"] = "An error occurred while updating the department: " + ex.Message;
                }
            }

            ViewBag.Managers = await _context.Employees
                .Select(e => new SelectListItem
                {
                    Value = e.EmployeeID.ToString(),
                    Text = $"{e.FirstName} {e.LastName}"
                }).ToListAsync();
            return View(department);
        }

        private int GetCurrentUserId()
        {
            return int.Parse(User.FindFirstValue("UserID") ?? "0");
        }


        // View Position List
        public async Task<IActionResult> Position(int page = 1, int pageSize = 10)
        {
            if (!IsUserAuthenticated())
            {
                return RedirectToLogin();
            }

            var totalPositions = await _context.Positions.CountAsync();
            var totalPages = (int)Math.Ceiling(totalPositions / (double)pageSize);

            var positions = await _context.Positions
                .Skip((page - 1) * pageSize)
                .Take(pageSize)
                .ToListAsync();

            ViewBag.CurrentPage = page;
            ViewBag.TotalPages = totalPages;

            return View(positions);
        }


        // Add Position Page (GET)
        [HttpGet]
        public IActionResult AddPosition()
        {
            if (!IsUserAuthenticated())
            {
                return RedirectToLogin();
            }

            return View();
        }

        // Add Position Page (POST)
        [HttpPost]
        public async Task<IActionResult> AddPosition(HRPayrollSystem.Models.Position position)
        {
            if (!IsUserAuthenticated())
            {
                return RedirectToLogin();
            }

            if (ModelState.IsValid)
            {
                _context.Positions.Add(position);
                await _context.SaveChangesAsync();
                var userID = HttpContext.Session.GetInt32("UserID");
                await LogAudit(userID ?? 0, $"Created new Position: {position.PositionTitle}");
                return RedirectToAction("Position");
            }

            return View(position);
        }


        public async Task<IActionResult> Myprofile()
        {
            if (!IsUserAuthenticated())
            {
                return RedirectToLogin();
            }

            int? user = HttpContext.Session.GetInt32("UserID");
            int?  employeeID = HttpContext.Session.GetInt32("EmployeeID");

            if (employeeID == null)
            {
                return RedirectToAction("Login", "Auth");
            }

            if (user == null)
            {
                return RedirectToAction("Login", "Auth");
            }



            if (user.HasValue && employeeID.HasValue)
            {
                // Fetch employee with related data from the database
                var employee = await _context.Employees
                    .Include(e => e.Department)
                    .Include(e => e.Position)
                    .Include(e => e.SalaryGrade)
                    .FirstOrDefaultAsync(e => e.EmployeeID == employeeID);

                if (employee != null)
                {
                    // Get documents (you may want to fetch specific document data based on your DB)
                    var documents = new List<string>
                    {
                        employee.PagIbigDoc,
                        employee.SSSDoc,
                        employee.PhilHealthDoc,
                        employee.BirthCertificateDoc
                    };

                    // Passing employee and documents to the view
                    ViewBag.Employee = employee;
                    ViewBag.JobDetails = new
                    {
                        Position = employee.Position?.PositionTitle,
                        Department = employee.Department?.DepartmentName,
                        HireDate = employee.HireDate?.ToString("MM/dd/yyyy")
                    };
                    ViewBag.BankInfo = new
                    {
                        PaypalEmail = employee.Email, // Assuming email as Paypal Email
                        TIN = employee.ContactNumber
                    };
                    ViewBag.Documents = documents;
                }
            }

            return View();
        }

        [HttpPost]
        public async Task<IActionResult> UploadDocument(IFormFile DocumentFile, string DocumentType)
        {
            if (!IsUserAuthenticated())
            {
                return RedirectToLogin();
            }

            var employeeID = HttpContext.Session.GetInt32("EmployeeID");
            if (employeeID == null || DocumentFile == null || string.IsNullOrEmpty(DocumentType))
            {
                TempData["Error"] = "Missing required fields.";
                return RedirectToAction("Myprofile");
            }

            var employee = await _context.Employees.FindAsync(employeeID.Value);
            if (employee == null)
            {
                TempData["Error"] = "Employee not found.";
                return RedirectToAction("Myprofile");
            }

            // Save file to wwwroot/uploads
            var uploadsFolder = Path.Combine(_webHostEnvironment.WebRootPath, "uploads");
            if (!Directory.Exists(uploadsFolder))
                Directory.CreateDirectory(uploadsFolder);

            var uniqueFileName = $"{Guid.NewGuid()}_{DocumentFile.FileName}";
            var filePath = Path.Combine(uploadsFolder, uniqueFileName);
            using (var fileStream = new FileStream(filePath, FileMode.Create))
            {
                await DocumentFile.CopyToAsync(fileStream);
            }

            // Save filename to corresponding document field
            switch (DocumentType)
            {
                case "PagIbig":
                    employee.PagIbigDoc = uniqueFileName;
                    break;
                case "SSS":
                    employee.SSSDoc = uniqueFileName;
                    break;
                case "PhilHealth":
                    employee.PhilHealthDoc = uniqueFileName;
                    break;
                case "BirthCertificate":
                    employee.BirthCertificateDoc = uniqueFileName;
                    break;
                default:
                    TempData["Error"] = "Invalid document type.";
                    return RedirectToAction("Myprofile");
            }

            _context.Employees.Update(employee);
            await _context.SaveChangesAsync();

            TempData["Success"] = "Document uploaded successfully.";
            return RedirectToAction("Myprofile");
        }

        public async Task<IActionResult> DownloadDocument(int id, string documentType)
        {
            var employee = await _context.Employees.FindAsync(id);
            if (employee == null) return NotFound();

            string fileName = "";
            string filePath = "";

            switch (documentType.ToLower())
            {
                case "sss":
                    fileName = employee.SSSDoc;
                    break;
                case "philhealth":
                    fileName = employee.PhilHealthDoc;
                    break;
                case "pagibig":
                    fileName = employee.PagIbigDoc;
                    break;
                case "birthcertificate":
                    fileName = employee.BirthCertificateDoc;
                    break;
                default:
                    return NotFound();
            }

            if (string.IsNullOrEmpty(fileName) || fileName == "--")
            {
                TempData["Error"] = "Document not found.";
                return RedirectToAction("Details", new { id = id });
            }

            filePath = Path.Combine(_webHostEnvironment.WebRootPath, "uploads", fileName);

            if (!System.IO.File.Exists(filePath))
            {
                TempData["Error"] = "Document file not found on server.";
                return RedirectToAction("Details", new { id = id });
            }

            var memory = new MemoryStream();
            using (var stream = new FileStream(filePath, FileMode.Open))
            {
                await stream.CopyToAsync(memory);
            }
            memory.Position = 0;

            var userID = HttpContext.Session.GetInt32("UserID");
            await LogAudit(userID ?? 0, $"Downloaded document for {employee.FirstName} {employee.LastName}");

            return File(memory, "application/octet-stream", fileName);
        }

        [Authorize]
        [HttpGet]
        public IActionResult EditProfile()
        {
            var employeeId = HttpContext.Session.GetInt32("EmployeeID");
            if (employeeId == null)
                return RedirectToAction("Login", "Auth");
            var employee = _context.Employees.FirstOrDefault(e => e.EmployeeID == employeeId);
            if (employee == null)
                return NotFound();
            return View(employee);
        }

        [Authorize]
        [HttpPost]
        [ValidateAntiForgeryToken]
        public IActionResult EditProfile(HRPayrollSystem.Models.Employee model)
        {
            var employeeId = HttpContext.Session.GetInt32("EmployeeID");
            if (employeeId == null)
                return RedirectToAction("Login", "Auth");
            var employee = _context.Employees.FirstOrDefault(e => e.EmployeeID == employeeId);
            if (employee == null)
                return NotFound();
            // Only update editable fields
            employee.ContactNumber = model.ContactNumber;
            employee.Address = model.Address;
            employee.Email = model.Email;
            // Add more fields if needed
            _context.SaveChanges();
            TempData["Success"] = "Profile updated successfully.";
            return RedirectToAction("Myprofile");
        }

        private bool VerifyPassword(string password, string storedHash)
        {
            byte[] storedHashBytes = Convert.FromBase64String(storedHash);

            // Extract the salt from the stored hash (first 16 bytes)
            byte[] salt = new byte[16];
            Buffer.BlockCopy(storedHashBytes, 0, salt, 0, 16);

            // Hash the provided password with the same salt
            var hash = new Rfc2898DeriveBytes(password, salt, 10000, HashAlgorithmName.SHA256);
            byte[] hashBytes = hash.GetBytes(32);

            // Compare the computed hash with the stored hash
            for (int i = 0; i < 32; i++)
            {
                if (hashBytes[i] != storedHashBytes[i + 16])
                {
                    return false;
                }
            }

            return true;
        }

        [Authorize]
        [HttpGet]
        public IActionResult ChangePassword()
        {
            return View();
        }

        [Authorize]
        [HttpPost]
        [ValidateAntiForgeryToken]
        public IActionResult ChangePassword(string currentPassword, string newPassword, string confirmPassword)
        {
            var employeeId = HttpContext.Session.GetInt32("EmployeeID");
            if (employeeId == null)
                return RedirectToAction("Login", "Auth");

            var user = _context.UserRoles.FirstOrDefault(u => u.EmployeeID == employeeId);
            if (user == null)
            {
                TempData["Error"] = "User not found.";
                return View();
            }

            // Validate current password
            if (string.IsNullOrEmpty(user.PasswordHash) || !VerifyPassword(currentPassword, user.PasswordHash))
            {
                TempData["Error"] = "Current password is incorrect.";
                return View();
            }

            // Validate new password match
            if (newPassword != confirmPassword)
            {
                TempData["Error"] = "New passwords do not match.";
                return View();
            }

            // Update password
            user.PasswordHash = HashPassword(newPassword);
            _context.SaveChanges();

            TempData["Success"] = "Password changed successfully.";
            return RedirectToAction("Myprofile");
        }

// You can reuse your existing HashPassword and VerifyPassword methods from AuthController.

        [Authorize(Roles = "HR, Admin")]
        [HttpPost]
        public async Task<IActionResult> ResetPassword(int userId)
        {
            if (!IsUserAuthenticated())
            {
                return RedirectToLogin();
            }

            try
            {
                var user = await _context.UserRoles.FindAsync(userId);
                if (user == null)
                {
                    TempData["Error"] = "User not found.";
                    return RedirectToAction("Roles");
                }

                // Reset password to default "123"
                user.PasswordHash = HashPassword("123");
                _context.Update(user);
                await _context.SaveChangesAsync();

                var userID = HttpContext.Session.GetInt32("UserID");
                await LogAudit(userID ?? 0, $"Reset password for user '{user.Username}' to default");

                TempData["Success"] = $"Password for user '{user.Username}' has been reset to default (123).";
            }
            catch (Exception ex)
            {
                TempData["Error"] = "An error occurred while resetting the password.";
                Console.WriteLine(ex.Message);
            }

            return RedirectToAction("Roles");
        }

    }

    public class ErrorsController : BaseController
    {
        public ErrorsController(AppDbContext context) : base(context)
        {
        }

        public IActionResult Error404()
        {
            return View();
        }

        public IActionResult Error500()
        {
            return View();
        }
        
    }



    [Authorize(Roles = "HR, Employee, Admin, PayrollStaff")]
    public class AnnouncementController : BaseController
    {
        private readonly AuditLogService _audit;
        public AnnouncementController(AppDbContext context, AuditLogService audit) : base(context) {
            _audit = audit;
        }

        public async Task<IActionResult> Notices(string category = "All", int page = 1)
        {
            if (!IsUserAuthenticated())
            {
                return RedirectToLogin();
            }

            int pageSize = 10;

            var noticesQuery = _context.Announcements
                .Where(a => a.ExpiryDate == null || a.ExpiryDate > DateTime.Now)
                .OrderByDescending(a => a.DatePosted)
                .AsQueryable();

            // Apply category filter
            if (!string.IsNullOrEmpty(category) && category.ToLower() != "all")
            {
                noticesQuery = noticesQuery.Where(a => a.MessageType.ToLower() == category.ToLower());
            }

            int totalItems = await noticesQuery.CountAsync();
            int totalPages = (int)Math.Ceiling((double)totalItems / pageSize);

            var paginatedNotices = await noticesQuery
                .Skip((page - 1) * pageSize)
                .Take(pageSize)
                .ToListAsync();

            // Pass data to View
            ViewBag.CurrentPage = page;
            ViewBag.TotalPages = totalPages;
            ViewBag.SelectedCategory = category.ToLower();

            return View(paginatedNotices);
        }




        public IActionResult Details(int id)
        {
            var notice = _context.Announcements.FirstOrDefault(a => a.AnnouncementID == id);

            if (notice == null)
            {
                return NotFound();
            }

            return View(notice);
        }





        public IActionResult Create()
        {
            if (!IsUserAuthenticated())
            {
                return RedirectToLogin();
            }

            return View();
        }

        [Authorize(Roles = "HR, Admin, PayrollStaff")]
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Create(CreateAnnouncementViewModel model)
        {
            if (!IsUserAuthenticated())
            {
                return RedirectToLogin();
            }

            var announcement = new Announcements
            {
                Title = model.Title,
                Message = model.Message,
                MessageType = model.MessageType,
                TargetType = model.TargetType,
                DatePosted = DateTime.Now,
                ExpiryDate = model.ExpiryDate,
                CreatedBy = HttpContext.Session.GetInt32("UserID")
            };

            _context.Announcements.Add(announcement);
            await _context.SaveChangesAsync();

            var userID = HttpContext.Session.GetInt32("UserID");
            await LogAudit(userID ?? 0, $"Created new announcement: {model.Title}");

            TempData["SuccessMessage"] = "Announcement successfully created!";
            return RedirectToAction("Create");
        }

        [HttpGet]
        public async Task<IActionResult> GetUnreadNotifications()
        {
            if (!IsUserAuthenticated())
            {
                return Json(new { error = "Unauthorized" }, 401);
            }

            var employeeId = HttpContext.Session.GetInt32("EmployeeID");
            var department = await _context.Employees
                .Where(e => e.EmployeeID == employeeId)
                .Select(e => e.Department.DepartmentName)
                .FirstOrDefaultAsync();

            var notifications = await _context.Announcements
                .Where(a => (a.TargetType == "All" || a.TargetType == department) &&
                           (a.ExpiryDate == null || a.ExpiryDate > DateTime.Now) &&
                           a.DatePosted > DateTime.Now.AddDays(-7))
                .OrderByDescending(a => a.DatePosted)
                .Take(10)
                .ToListAsync();

            // Get read IDs from session
            var readIds = HttpContext.Session.GetString("ReadNotificationIds");
            List<int> readList = string.IsNullOrEmpty(readIds)
                ? new List<int>()
                : readIds.Split(',').Select(int.Parse).ToList();

            // Only return unread
            var unreadNotifications = notifications
                .Where(a => !readList.Contains(a.AnnouncementID))
                .Select(a => new
                {
                    id = a.AnnouncementID,
                    title = a.Title,
                    message = a.Message,
                    datePosted = a.DatePosted,
                    type = a.MessageType
                })
                .ToList();

            return Json(unreadNotifications);
        }

        [HttpPost]
        public IActionResult MarkAsRead([FromBody] NotificationReadModel model)
        {
            if (!IsUserAuthenticated())
            {
                return Json(new { success = false, error = "Unauthorized" }, 401);
            }

            // Get the list of read notification IDs from session
            var readIds = HttpContext.Session.GetString("ReadNotificationIds");
            List<int> readList = string.IsNullOrEmpty(readIds)
                ? new List<int>()
                : readIds.Split(',').Select(int.Parse).ToList();

            // Add the new ID if not already present
            if (!readList.Contains(model.Id))
                readList.Add(model.Id);

            // Save back to session
            HttpContext.Session.SetString("ReadNotificationIds", string.Join(",", readList));

            return Json(new { success = true });
        }

        public class NotificationReadModel
        {
            public int Id { get; set; }
        }


        
    }


    // Add this new service class
    public class AttendanceBackgroundService : BackgroundService
    {
        private readonly IServiceProvider _services;
        private readonly ILogger<AttendanceBackgroundService> _logger;

        public AttendanceBackgroundService(
            IServiceProvider services,
            ILogger<AttendanceBackgroundService> logger)
        {
            _services = services;
            _logger = logger;
        }

        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            while (!stoppingToken.IsCancellationRequested)
            {
                try
                {
                    // Check if it's the end of the day (e.g., 11:59 PM)
                    if (DateTime.Now.Hour == 23 && DateTime.Now.Minute == 59)
                    {
                        using (var scope = _services.CreateScope())
                        {
                            var context = scope.ServiceProvider.GetRequiredService<AppDbContext>();
                            var auditService = scope.ServiceProvider.GetRequiredService<AuditLogService>();
                            var controller = new AttendanceController(context, auditService);

                            await controller.MarkAbsentEmployees();
                            _logger.LogInformation("Marked absent employees for the day");
                        }
                    }

                    // Wait for 1 minute before checking again
                    await Task.Delay(TimeSpan.FromMinutes(1), stoppingToken);
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Error occurred while marking absent employees");
                }
            }
        }
    }

    

}




        

