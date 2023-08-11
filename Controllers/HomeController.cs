using IpGetter.Models;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using System.Diagnostics;

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

            if (serverVariables == null)
            {
                return "";
            }
            string ip = serverVariables["HTTP_INCAP_CLIENT_IP"] ?? "";

            ip = "217.33.150.98:51187";

            

            if (string.IsNullOrEmpty(ip))
            {
                ip = Request.Headers["INCAP-CLIENT-IP"];
            }

            if (string.IsNullOrEmpty(ip))
            {
                ip = serverVariables["HTTP_X_FORWARDED_FOR"] ?? "";
            }

            if (string.IsNullOrEmpty(ip))
            {
                ip = Request.Headers["X-Forwarded-For"];
            }

            if (string.IsNullOrEmpty(ip))
            {
                ip = serverVariables["HTTP_TRUE_CLIENT_IP"] ?? "";
            }

            if (string.IsNullOrEmpty(ip))
            {
                ip = Request.Headers["True-Client-IP"];
            }

            if (string.IsNullOrEmpty(ip))
            {
                ip = serverVariables["REMOTE_ADDR"] ?? "";
            }

            if (string.IsNullOrEmpty(ip))
            {
                ip = Request.HttpContext?.Connection?.RemoteIpAddress?.MapToIPv4().ToString() ?? "";
            }

            if (!string.IsNullOrEmpty(ip) && ip.Contains(":"))
            {
                var index = ip.IndexOf(':');
                ip = ip.Substring(0, index);
            }

            model.ProcessedIp = ip;

            return View(model);
        }

        private string? Get_HTTP_INCAP_CLIENT_IP(IServerVariablesFeature serverVariables) => serverVariables["HTTP_INCAP_CLIENT_IP"] ?? "";
        private string? Get_HTTP_X_FORWARDED_FOR(IServerVariablesFeature serverVariables) => serverVariables["HTTP_X_FORWARDED_FOR"] ?? "";
        private string? Get_HTTP_TRUE_CLIENT_IP(IServerVariablesFeature serverVariables) => serverVariables["HTTP_TRUE_CLIENT_IP"] ?? "";

        private string? Get_INCAP_CLIENT_IP(HttpRequest request) => request.Headers["INCAP-CLIENT-IP"];
        private string? Get_X_Forwarded_For(HttpRequest request) => request.Headers["X-Forwarded-For"];
        private string? Get_True_Client_IP(HttpRequest request) => request.Headers["True-Client-IP"];

        private string? Get_RemoteIpAddress(HttpRequest request) => request.HttpContext?.Connection?.RemoteIpAddress?.MapToIPv4().ToString() ?? "";
    }
}