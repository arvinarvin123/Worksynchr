using Vonage;
using Vonage.Request;
using Vonage.Verify;

public class VonageService : IVonageService
{
    private readonly VonageClient _vonageClient;
    private readonly IConfiguration _config;

    public VonageService(IConfiguration config)
    {
        _config = config;
        var credentials = Credentials.FromApiKeyAndSecret(
            _config["Vonage:ApiKey"],
            _config["Vonage:ApiSecret"]
        );

        _vonageClient = new VonageClient(credentials);
    }

    public async Task<string> SendVerificationAsync(string phoneNumber)
    {
        var request = new VerifyRequest
        {
            Number = phoneNumber,
            Brand = _config["Vonage:Brand"]
        };

        var result = await _vonageClient.VerifyClient.VerifyRequestAsync(request);
        return result.RequestId;
    }

    public async Task<bool> CheckVerificationAsync(string requestId, string code)
    {
        var checkRequest = new VerifyCheckRequest
        {
            RequestId = requestId,
            Code = code
        };

        var result = await _vonageClient.VerifyClient.VerifyCheckAsync(checkRequest);
        return result.Status == "0"; // 0 means success
    }
}
