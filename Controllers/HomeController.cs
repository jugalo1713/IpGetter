using IpGetter.Models;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.Mvc;
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
            var moodel = new IpModel();

            var serverVariables = Request.HttpContext.Features.Get<IServerVariablesFeature>();

            if(serverVariables != null)
            {
                moodel.HTTP_INCAP_CLIENT_IP = Get_HTTP_INCAP_CLIENT_IP(serverVariables);
                moodel.HTTP_X_FORWARDED_FOR = Get_HTTP_X_FORWARDED_FOR(serverVariables);
                moodel.HTTP_TRUE_CLIENT_IP = Get_HTTP_TRUE_CLIENT_IP(serverVariables);
            }

            if(Request != null)
            {
                moodel.INCAP_CLIENT_IP = Get_INCAP_CLIENT_IP(Request);
                moodel.X_Forwarded_For = Get_X_Forwarded_For(Request);
                moodel.True_Client_IP = Get_True_Client_IP(Request);
                moodel.RemoteIpAddress = Get_RemoteIpAddress(Request);
            }

            return View(moodel);
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