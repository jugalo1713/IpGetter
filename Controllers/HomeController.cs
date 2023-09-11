using IpGetter.Models;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.Mvc;

namespace IpGetter.Controllers
{
    public class HomeController : Controller
    {
        private readonly ILogger<HomeController> _logger;

        public HomeController(ILogger<HomeController> logger)
        {
            _logger = logger;
        }

        public IActionResult Index()
        {
            var model = new IpModel();

            var serverVariables = Request.HttpContext.Features.Get<IServerVariablesFeature>();

            if(serverVariables != null)
            {
                model.HTTP_INCAP_CLIENT_IP = Get_HTTP_INCAP_CLIENT_IP(serverVariables);
                model.HTTP_X_FORWARDED_FOR = Get_HTTP_X_FORWARDED_FOR(serverVariables);
                model.HTTP_TRUE_CLIENT_IP = Get_HTTP_TRUE_CLIENT_IP(serverVariables);
            }

            if(Request != null)
            {
                model.INCAP_CLIENT_IP = Get_INCAP_CLIENT_IP(Request);
                model.X_Forwarded_For = Get_X_Forwarded_For(Request);
                model.True_Client_IP = Get_True_Client_IP(Request);
                model.RemoteIpAddress = Get_RemoteIpAddress(Request);
            }

            model.ProcessedIp = processedIp(serverVariables);
            model.SecondWay = GetUserIPAddress2(serverVariables);

            return View(model);
        }

        private string? Get_HTTP_INCAP_CLIENT_IP(IServerVariablesFeature serverVariables) => serverVariables["HTTP_INCAP_CLIENT_IP"] ?? "";
        private string? Get_HTTP_X_FORWARDED_FOR(IServerVariablesFeature serverVariables) => serverVariables["HTTP_X_FORWARDED_FOR"] ?? "";
        private string? Get_HTTP_TRUE_CLIENT_IP(IServerVariablesFeature serverVariables) => serverVariables["HTTP_TRUE_CLIENT_IP"] ?? "";
        private string? Get_INCAP_CLIENT_IP(HttpRequest request) => request.Headers["INCAP-CLIENT-IP"];
        private string? Get_X_Forwarded_For(HttpRequest request) => request.Headers["X-Forwarded-For"];
        private string? Get_True_Client_IP(HttpRequest request) => request.Headers["True-Client-IP"];
        private string? Get_RemoteIpAddress(HttpRequest request) => request.HttpContext?.Connection?.RemoteIpAddress?.MapToIPv4().ToString() ?? "";

        private string? processedIp(IServerVariablesFeature serverVariables)
        {
            var headerKeys = new[] {"HTTP_INCAP_CLIENT_IP", "HTTP_X_FORWARDED_FOR",
            "HTTP_TRUE_CLIENT_IP", "REMOTE_ADDR",
            "INCAP-CLIENT-IP", "X-Forwarded-For", "True-Client-IP"};

            string ip = "";

            if (serverVariables != null)
            {
                ip = headerKeys.Select(key => serverVariables[key]).FirstOrDefault(value => !string.IsNullOrEmpty(value)) ?? "";
            }

            if (string.IsNullOrEmpty(ip) && Request.Headers != null)
            {
                ip = headerKeys.Select(key => Request.Headers[key]).FirstOrDefault(value => !string.IsNullOrEmpty(value));
            }

            if (string.IsNullOrEmpty(ip) && Request.HttpContext?.Connection?.RemoteIpAddress != null)
            {
                ip = Request.HttpContext?.Connection?.RemoteIpAddress?.MapToIPv4().ToString() ?? "";
            }

            //if (!string.IsNullOrEmpty(ip) && ip.Contains(':'))
            //{
            //    var index = ip.IndexOf(':');
            //    ip = ip[..index];
            //}

            return ip;
        }


        public string GetUserIPAddress2(IServerVariablesFeature serverVariables)
        {
            var request = Request;
            string? ip = "";

            var headerKeys = new[] {"HTTP_INCAP_CLIENT_IP", "HTTP_X_FORWARDED_FOR",
            "HTTP_TRUE_CLIENT_IP", "REMOTE_ADDR",
            "INCAP-CLIENT-IP", "X-Forwarded-For", "True-Client-IP"};

            foreach (var key in headerKeys)
            {
                ip = serverVariables[key];
                if (!string.IsNullOrEmpty(ip)) break;

                ip = request.Headers[key];
                if (!string.IsNullOrEmpty(ip)) break;
            }

            if (string.IsNullOrEmpty(ip))
            {
                ip = request.HttpContext?.Connection?.RemoteIpAddress?.MapToIPv4().ToString();
            }

            return ip;
        }
    }
}