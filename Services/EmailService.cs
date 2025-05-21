using SendGrid;
using SendGrid.Helpers.Mail;
using Microsoft.Extensions.Configuration;

namespace HRPayrollSystem.Services
{
    public class EmailService
    {
        private readonly string _apiKey;

        public EmailService(IConfiguration configuration)
        {
            _apiKey = configuration["SendGrid:ApiKey"];
        }

        // Existing SendEmailAsync method
        public async Task SendEmailAsync(string toEmail, string subject, string message)
        {
            var client = new SendGridClient(_apiKey);
            var from = new EmailAddress("l.villapaz.539636@umindanao.edu.ph", "WorkSync");
            var to = new EmailAddress(toEmail);
            var plainTextContent = message;
            var htmlContent = $"<strong>{message}</strong>";

            var msg = MailHelper.CreateSingleEmail(from, to, subject, plainTextContent, htmlContent);
            var response = await client.SendEmailAsync(msg);

            if (!response.IsSuccessStatusCode)
            {
                var error = await response.Body.ReadAsStringAsync();
                throw new Exception($"SendGrid failed: {response.StatusCode} - {error}");
            }
        }

        // New method to send payroll reimbursement email
        public async Task SendPayrollEmailAsync(string recipientEmail, string name, decimal amount)
        {
            var subject = "Your Payroll Has Been Credited via PayPal";
            var message = $"Hi {name},\n\nYou've received a payroll reimbursement of ₱{amount:N2} via PayPal.\n\nThank you!";

            await SendEmailAsync(recipientEmail, subject, message);
        }
    }
}
