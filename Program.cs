using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Net.Http;
using System.IO;
using System.Security.Cryptography;

namespace srun_login
{
    class Program
    {
        private static readonly HttpClient client = new HttpClient();

        private static string baseUrl;
        private static string username;
        private static string password;
        private static string challenge;
        private static string userIp;

        private static readonly string enc = "srun_bx1";
        private static readonly int n = 200;
        private static readonly int type = 1;
        private static readonly string ac_id = "1";

        static async Task Main(string[] args)
        {
            Setup();

            await GetChallenge();

            await Login();

            Console.ReadKey();
        }

        private static void Setup()
        {
            string path = "user.dat";
            using (StreamReader sr = File.OpenText(path))
            {
                baseUrl = sr.ReadLine().Trim();
                username = sr.ReadLine().Trim();
                password = sr.ReadLine().Trim();
            }

            client.DefaultRequestHeaders.Clear();
            client.DefaultRequestHeaders.Add("Accept", "text/javascript, application/javascript, application/ecmascript, application/x-ecmascript, */*; q=0.01");
            client.DefaultRequestHeaders.Add("Accept-Encoding", "gzip, deflate");
            client.DefaultRequestHeaders.Add("Accept-Language", "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2");
            client.DefaultRequestHeaders.Add("Connection", "keep-alive");
            client.DefaultRequestHeaders.Add("Cookie", "lang=zh-CN");
            client.DefaultRequestHeaders.Add("Host", "10.248.98.2");
            client.DefaultRequestHeaders.Add("Referer", "http://10.248.98.2/srun_portal_pc?ac_id=1&theme=basic2");
            client.DefaultRequestHeaders.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:92.0) Gecko/20100101 Firefox/92.0");
            client.DefaultRequestHeaders.Add("X-Requested-With", "XMLHttpRequest");
        }

        private static async Task GetChallenge()
        {
            string param = $"?callback=jQuery112405953212365516434_{DateTimeOffset.Now.ToUnixTimeMilliseconds()}"
                + $"&username={username}"
                + $"&_={DateTimeOffset.Now.ToUnixTimeMilliseconds()}";
            string responseBody = await client.GetStringAsync(baseUrl + "/cgi-bin/get_challenge" + param);
            string jsonString = responseBody.Split(new char[] { '(', ')' })[1];

            foreach (var pair in jsonString.Split(','))
            {
                if (pair.Contains("challenge"))
                {
                    challenge = pair.Split(':')[1].Trim('\"');
                }
                else if (pair.Contains("client_ip"))
                {
                    userIp = pair.Split(':')[1].Trim('\"');
                }
            }

            Console.WriteLine($"challenge = {challenge}");
            Console.WriteLine($"IP = {userIp}");
        }

        private static async Task Login()
        {
            var info = new Info
            {
                username = username,
                password = password,
                ip = userIp,
                acid = ac_id,
                enc_ver = enc
            };
            string i = CalcInfo(info, challenge);
            string hmd5 = CalcPwd(password, challenge);
            string chkstr = challenge + username;
            chkstr += challenge + hmd5;
            chkstr += challenge + info.acid;
            chkstr += challenge + userIp;
            chkstr += challenge + n;
            chkstr += challenge + type;
            chkstr += challenge + i;

            info.password = "{MD5}" + hmd5;

            string param = $"?callback=jQuery112405953212365516434_{DateTimeOffset.Now.ToUnixTimeMilliseconds()}"
                + "&action=login"
                + $"&username={username}"
                + $"&password={info.password}"
                + $"&ac_id={ac_id}"
                + $"&ip={userIp}"
                + $"&chksum={CalcChksum(chkstr)}"
                + $"&info={i.Replace("+", "%2B").Replace("/", "%2F").Replace("=", "%3D")}"
                + $"&n={n}"
                + $"&type={type}"
                + $"&os=Windows+10"
                + $"&name=Windows"
                + $"&double_stack=0"
                + $"&_={DateTimeOffset.Now.ToUnixTimeMilliseconds()}";
            
            string responseBody = await client.GetStringAsync(baseUrl + "/cgi-bin/srun_portal" + param);
            string jsonString = responseBody.Split(new char[] { '(', ')' })[1];

            foreach (var pair in jsonString.Split(','))
            {
                if (pair.Contains("error"))
                {
                    Console.WriteLine($"result = {pair.Split(':')[1].Trim('\"')}");
                    break;
                }
            }
        }

        private static string CalcInfo(Info data, string key)
        {
            string jsonString = data.ToJsonString();

            string xString = XEncode.Encode(jsonString, key);

            return "{SRBX1}" + Base64Alt.Encode(xString);
        }

        private static string CalcPwd(string data, string key)
        {
            byte[] hash;
            using (HMAC hmac = new HMACMD5(Encoding.Default.GetBytes(key)))
            {
                hash = hmac.ComputeHash(Encoding.Default.GetBytes(data));
            }

            var res = new StringBuilder();
            for (var i = 0; i < hash.Length; i++)
            {
                res.Append(hash[i].ToString("x2"));
            }

            return res.ToString();
        }

        private static string CalcChksum(string data)
        {
            byte[] hash;
            using (SHA1 sha1 = SHA1.Create())
            {

                hash = sha1.ComputeHash(Encoding.Default.GetBytes(data));
            }

            var res = new StringBuilder();
            for (var i = 0; i < hash.Length; i++)
            {
                res.Append(hash[i].ToString("x2"));
            }

            return res.ToString();
        }
    }
}
