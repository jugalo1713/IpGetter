namespace IpGetter.Models
{
    public class IpModel
    {
        public string? HTTP_INCAP_CLIENT_IP { get; set; }
        public string? INCAP_CLIENT_IP { get; set; }
        public string? HTTP_X_FORWARDED_FOR { get; set; }
        public string? X_Forwarded_For { get; set; }
        public string? HTTP_TRUE_CLIENT_IP { get; set; }
        public string? True_Client_IP { get; set; }
        public string? RemoteIpAddress { get; set; }
        public string? ProcessedIp { get; set; }
        public string? SecondWay { get; set; }

    }
}
