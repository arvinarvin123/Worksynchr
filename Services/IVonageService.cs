public interface IVonageService
{
    Task<string> SendVerificationAsync(string phoneNumber);
    Task<bool> CheckVerificationAsync(string requestId, string code);
}
