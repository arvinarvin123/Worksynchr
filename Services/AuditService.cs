using HRPayrollSystem.Models;
using Microsoft.AspNetCore.Http;
using Microsoft.EntityFrameworkCore;
using System;
using System.Threading.Tasks;
using HRPayrollSystem.Models;

public class AuditLogService
{
    private readonly AppDbContext _context;
    private readonly IHttpContextAccessor _httpContextAccessor;

    public AuditLogService(AppDbContext context, IHttpContextAccessor httpContextAccessor)
    {
        _context = context;
        _httpContextAccessor = httpContextAccessor;
    }

    public async Task LogAsync(int userId, string actionTaken)
    {
        // Check if the user exists in UserRoles
        var userExists = await _context.UserRoles.AnyAsync(ur => ur.UserID == userId);

        var ip = _httpContextAccessor.HttpContext?.Connection?.RemoteIpAddress?.ToString() ?? "Unknown";

        if (!userExists)
        {
            // If the user does not exist, log an error or throw an exception
            throw new Exception($"User with ID {userId} does not exist in UserRoles.");
        }

        // Now proceed with logging the action
        var log = new AuditLog
        {
            UserID = userId,
            ActionTaken = actionTaken,
            Timestamp = DateTime.Now,
            IPAddress = ip
        };

        _context.AuditLogs.Add(log);
        await _context.SaveChangesAsync();
    }

}
