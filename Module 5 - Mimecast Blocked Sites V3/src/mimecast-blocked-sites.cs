using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace Mimecast_Block_App
{
    public partial class Form1 : Form
    {
        public Form1()
        {
            InitializeComponent();
        }

        private void Form1_Load(object sender, EventArgs e)
        {
            status.Text = "Waiting for user action ...";
        }

        private void button3_Click(object sender, EventArgs e)
        {
            System.Environment.Exit(0);
        }

        private void button1_Click(object sender, EventArgs e)
        {
            AddBlockedSite();
        }

        public void AddBlockedSite()
        {
            //Setup required variables - ENTER YOUR OWN HERE
            string baseUrl = "https://us-api.mimecast.com";
            string uri = "/api/directory/add-group-member";
            string accessKey = "";
            string secretKey = "";
            string appId = "";
            string appKey = "";
            string blockedsenderid = "";

            //Code borrowed from Mimecast's API Documentation with modifications to work with this application
            //Generate request header values
            string hdrDate = System.DateTime.Now.ToUniversalTime().ToString("R");
            string requestId = System.Guid.NewGuid().ToString();

            //Create the HMAC SHA1 of the Base64 decoded secret key for the Authorization header
            System.Security.Cryptography.HMAC h = new System.Security.Cryptography.HMACSHA1(System.Convert.FromBase64String(secretKey));

            //Use the HMAC SHA1 value to sign the hdrDate + ":" requestId + ":" + URI + ":" + appkey
            byte[] hash = h.ComputeHash(System.Text.Encoding.Default.GetBytes(hdrDate + ":" + requestId + ":" + uri + ":" + appKey));

            //Build the signature to be included in the Authorization header in your request
            string signature = "MC " + accessKey + ":" + System.Convert.ToBase64String(hash);
            //Build Request
            System.Net.HttpWebRequest request = (System.Net.HttpWebRequest)System.Net.WebRequest.Create(baseUrl + uri);
            request.Method = "POST";
            request.ContentType = "application/json";

            //Add Headers
            request.Headers[System.Net.HttpRequestHeader.Authorization] = signature;
            request.Headers.Add("x-mc-date", hdrDate);
            request.Headers.Add("x-mc-req-id", requestId);
            request.Headers.Add("x-mc-app-id", appId);

            // checks to see if domain or e-mail address is checked
            if ((rb_domain.Checked == false) & (rb_email.Checked ==false))
            {
                status.Text = ("Please check domain or e-mail!");
            }
            if (rb_domain.Checked == true)
            {
                status.Text = ("Domain selected.");
                if (CheckDomain(tb_entry.Text))
                {
                    status.Text = ("Domain is valid.");

                    //Add request body
                    //Create and write data to stream
                    string postData = "{\"data\": [{\"id\": \"" + blockedsenderid + "\",\"domain\": \"" + tb_entry.Text + "\"}]}";

                    byte[] payload = System.Text.Encoding.UTF8.GetBytes(postData);

                    System.IO.Stream stream = request.GetRequestStream();
                    stream.Write(payload, 0, payload.Length);
                    stream.Close();

                    //Send Request
                    System.Net.HttpWebResponse response = (System.Net.HttpWebResponse)request.GetResponse();

                    //Output response to console
                    System.IO.StreamReader reader = new System.IO.StreamReader(response.GetResponseStream());
                    string responseBody = "";
                    string temp = null;
                    while ((temp = reader.ReadLine()) != null)
                    {
                        responseBody += temp;
                    };

                    //json parsing variables - this will retrieve the meta and failure messages to confirm successful entries from Mimecast's API
                    var jsonDoc = JsonDocument.Parse(responseBody);
                    var root = jsonDoc.RootElement;
                    var entrystatus = root.GetProperty("meta");
                    var entryfailstatus = root.GetProperty("fail");

                    //error handling and updating status if status is 200 and no failures this means the site was successfully added, if not it confirms status ok but there were failures
                    if (entrystatus.ToString() == "{\"status\":200}")
                    {
                        if (entryfailstatus.ToString() == "[]")
                        {
                            status.Text = ("Domain added successfully.");
                        }
                        else
                        {
                            status.Text = ("Status OK but failures present!");
                        }
                    }
                    else
                    {
                        status.Text = ("Domain not blocked, status failed.");
                    }
                }
                else
                {
                    status.Text = ("Domain is on free-email list, please recheck!");
                }
            }
            if (rb_email.Checked == true)
            {

                if (ValidateEmail(tb_entry.Text))
                {
                    status.Text = ("Valid e-mail");

                    //Add request body
                    //Create and write data to stream
                    string postData = "{\"data\": [{\"id\": \"" + blockedsenderid + "\",\"emailAddress\": \"" + tb_entry.Text + "\"}]}";

                    byte[] payload = System.Text.Encoding.UTF8.GetBytes(postData);

                    System.IO.Stream stream = request.GetRequestStream();
                    stream.Write(payload, 0, payload.Length);
                    stream.Close();

                    //Send Request
                    System.Net.HttpWebResponse response = (System.Net.HttpWebResponse)request.GetResponse();

                    //Output response to console
                    System.IO.StreamReader reader = new System.IO.StreamReader(response.GetResponseStream());
                    string responseBody = "";
                    string temp = null;
                    while ((temp = reader.ReadLine()) != null)
                    {
                        responseBody += temp;
                    };

                    //json parsing variables - this will retrieve the meta and failure messages to confirm successful entries
                    var jsonDoc = JsonDocument.Parse(responseBody);
                    var root = jsonDoc.RootElement;
                    var entrystatus = root.GetProperty("meta");
                    var entryfailstatus = root.GetProperty("fail");

                    //error handling and updating status if status is 200 and no failures this means the e-mail was successfully added, if not it confirms status ok but there were failures
                    if (entrystatus.ToString() == "{\"status\":200}")
                    {
                        if (entryfailstatus.ToString() == "[]")
                        {
                            status.Text = ("E-mail address added successfully.");
                        }
                        else
                        {
                            status.Text = ("Status OK but failures present!");
                        }
                    }
                    else
                    {
                        status.Text = ("E-mail address not blocked, status failed.");
                    }

                }
                else
                {
                    status.Text = ("E-mail address entered is not valid!");
                }
            }
        }
        //Check domain function - checks to see if domain entered is one of the free e-mail domains
        public bool CheckDomain (string entereddomain)
        {
            string[] freeemaildomains = { "aol.com", "articmail.com", "gmail.com", "outlook.com", "live.com", "hotmail.com", "protonmail.com", "yahoo.com", "zoho.com" };
            if (freeemaildomains.Contains(entereddomain))
            {
                return false;
            }
            else
            {
                return true;
            }
        }

        //Validate E-mail function - checks to see if entered email is valid
        public bool ValidateEmail(string enteredemail)
        {
            string pattern;
            pattern = @"^[\w\.\+\-]+\@[\w]+\.[a-z]{2,3}$";
            Regex rgx = new Regex(pattern);
            if (rgx.IsMatch(enteredemail))
            {
                return true;
            }
            else
            {
                return false;
            }
        }

        private void button2_Click(object sender, EventArgs e)
        {
            DecodeURL();
        }
        public void DecodeURL()
        {
            //Setup required variables - ENTER YOUR OWN HERE
            string baseUrl = "https://us-api.mimecast.com";
            string uri = "/api/ttp/url/decode-url";
            string accessKey = "";
            string secretKey = "";
            string appId = "";
            string appKey = "";

            //Code borrowed from Mimecast's API Documentation with modifications to work with this application
            //Generate request header values
            string hdrDate = System.DateTime.Now.ToUniversalTime().ToString("R");
            string requestId = System.Guid.NewGuid().ToString();

            //Create the HMAC SHA1 of the Base64 decoded secret key for the Authorization header
            System.Security.Cryptography.HMAC h = new System.Security.Cryptography.HMACSHA1(System.Convert.FromBase64String(secretKey));

            //Use the HMAC SHA1 value to sign the hdrDate + ":" requestId + ":" + URI + ":" + appkey
            byte[] hash = h.ComputeHash(System.Text.Encoding.Default.GetBytes(hdrDate + ":" + requestId + ":" + uri + ":" + appKey));

            //Build the signature to be included in the Authorization header in your request
            string signature = "MC " + accessKey + ":" + System.Convert.ToBase64String(hash);

            //Build Request
            System.Net.HttpWebRequest request = (System.Net.HttpWebRequest)System.Net.WebRequest.Create(baseUrl + uri);
            request.Method = "POST";
            request.ContentType = "application/json";

            //Add Headers
            request.Headers[System.Net.HttpRequestHeader.Authorization] = signature;
            request.Headers.Add("x-mc-date", hdrDate);
            request.Headers.Add("x-mc-req-id", requestId);
            request.Headers.Add("x-mc-app-id", appId);

            //Add request body
            //Create and write data to stream
            string postData = "{\"data\": [{\"url\": \"" + tb_url2decode.Text + "\"}]}";

            byte[] payload = System.Text.Encoding.UTF8.GetBytes(postData);

            System.IO.Stream stream = request.GetRequestStream();
            stream.Write(payload, 0, payload.Length);
            stream.Close();

            //Send Request
            System.Net.HttpWebResponse response = (System.Net.HttpWebResponse)request.GetResponse();

            //Output response to console
            System.IO.StreamReader reader = new System.IO.StreamReader(response.GetResponseStream());
            string responseBody = "";
            string temp = null;
            while ((temp = reader.ReadLine()) != null)
            {
                responseBody += temp;
            };

            //json parsing variables - this will retrieve the meta and failure messages to confirm successful entries from Mimecast's API
            var jsonDoc = JsonDocument.Parse(responseBody);
            var root = jsonDoc.RootElement;
            var entrystatus = root.GetProperty("meta");
            var entryfailstatus = root.GetProperty("fail");
            var urlholder1 = root.GetProperty("data");
            
            //string manipulation to extrapolate the decoded URL - could have used a class for json deserialization - next version will include this
            string urlholder2 = urlholder1.ToString();
            string decodedurl = urlholder2.Substring((9));


            //error handling and updating status if status is 200 and no failures this means the URL was decoded successfully, if not it confirms status ok but there were failures
            if (entrystatus.ToString() == "{\"status\":200}")
            {
                if (entryfailstatus.ToString() == "[]")
                {

                    tb_decodedurl.Text = (decodedurl.Split('\"')[0]);
                    status.Text = ("URL decoded successfully!");
                }
                else
                {
                    tb_decodedurl.Text = ("Status OK but failures present!");
                    status.Text = ("Status OK but failures present!");
                }
            }
            else
            {
                tb_decodedurl.Text = ("Could not decode URL, status failed!");
                status.Text = ("Could not decode URL, status failed!");
            }
        }

        private void button4_Click(object sender, EventArgs e)
        {
            BlockSite();
        }
        public void BlockSite()
        {
            //Setup required variables - ENTER YOUR OWN HERE
            string baseUrl = "https://us-api.mimecast.com";
            string uri = "/api/ttp/url/create-managed-url";
            string accessKey = "";
            string secretKey = "";
            string appId = "";
            string appKey = "";

            //Code borrowed from Mimecast's API Documentation with modifications to work with this application
            //Generate request header values
            string hdrDate = System.DateTime.Now.ToUniversalTime().ToString("R");
            string requestId = System.Guid.NewGuid().ToString();

            //Create the HMAC SHA1 of the Base64 decoded secret key for the Authorization header
            System.Security.Cryptography.HMAC h = new System.Security.Cryptography.HMACSHA1(System.Convert.FromBase64String(secretKey));

            //Use the HMAC SHA1 value to sign the hdrDate + ":" requestId + ":" + URI + ":" + appkey
            byte[] hash = h.ComputeHash(System.Text.Encoding.Default.GetBytes(hdrDate + ":" + requestId + ":" + uri + ":" + appKey));

            //Build the signature to be included in the Authorization header in your request
            string signature = "MC " + accessKey + ":" + System.Convert.ToBase64String(hash);
            
            //Build Request
            System.Net.HttpWebRequest request = (System.Net.HttpWebRequest)System.Net.WebRequest.Create(baseUrl + uri);
            request.Method = "POST";
            request.ContentType = "application/json";

            //Add Headers
            request.Headers[System.Net.HttpRequestHeader.Authorization] = signature;
            request.Headers.Add("x-mc-date", hdrDate);
            request.Headers.Add("x-mc-req-id", requestId);
            request.Headers.Add("x-mc-app-id", appId);

            //Error handling for when both radio buttons are not clicked.
            if ((rb_domainonly.Checked == false) & (rb_explicit.Checked == false))
            {
                status.Text = ("Please check domain only or explicit URL!");
            }

            //Catch to run domain only block
            if (rb_domainonly.Checked == true)
            {
                if (CheckDomain(tb_url2block.Text))
                {
                    status.Text = ("Domain is valid.");
                    //Sets matchtype variable to be domain
                    string matchtype = "domain";

                    //Add request body
                    //Create and write data to stream
                    string postData = "{\"data\": [{\"matchType\": \"" + matchtype + "\",\"disableRewrite\": False,\"action\": \"block\",\"comment\": \"" + tb_url2blockcomment.Text + "\",\"disableUserAwareness\": False,\"url\": \"" + tb_url2block.Text + "\",\"disableLogClick\": False}]}";



                    byte[] payload = System.Text.Encoding.UTF8.GetBytes(postData);

                    System.IO.Stream stream = request.GetRequestStream();
                    stream.Write(payload, 0, payload.Length);
                    stream.Close();

                    //Send Request
                    System.Net.HttpWebResponse response = (System.Net.HttpWebResponse)request.GetResponse();

                    //Output response to console
                    System.IO.StreamReader reader = new System.IO.StreamReader(response.GetResponseStream());
                    string responseBody = "";
                    string temp = null;
                    while ((temp = reader.ReadLine()) != null)
                    {
                        responseBody += temp;
                    };

                    //json parsing variables - this will retrieve the meta and failure messages to confirm successful entries from Mimecast's API
                    var jsonDoc = JsonDocument.Parse(responseBody);
                    var root = jsonDoc.RootElement;
                    var entrystatus = root.GetProperty("meta");
                    var entryfailstatus = root.GetProperty("fail");

                    //error handling and updating status if status is 200 and no failures this means the site was successfully added, if not it confirms status ok but there were failures
                    if (entrystatus.ToString() == "{\"status\":200}")
                    {
                        if (entryfailstatus.ToString() == "[]")
                        {
                            status.Text = ("Domain added successfully.");
                        }
                        else
                        {
                            status.Text = ("Status OK but failures present!");
                        }
                    }
                    else
                    {
                        status.Text = ("Domain not blocked, status failed.");
                    }

                }
                else
                {
                    status.Text = ("Domain is on free e-mail list, please recheck!");
                }

            }

            if (rb_explicit.Checked == true)
            {
                //Sets matchtype variable to be domain
                string matchtype = "explicit";

                //Add request body
                //Create and write data to stream
                string postData = "{\"data\": [{\"matchType\": \"" + matchtype + "\",\"disableRewrite\": False,\"action\": \"block\",\"comment\": \"" + tb_url2blockcomment.Text + "\",\"disableUserAwareness\": False,\"url\": \"" + tb_url2block.Text + "\",\"disableLogClick\": False}]}";

                byte[] payload = System.Text.Encoding.UTF8.GetBytes(postData);

                System.IO.Stream stream = request.GetRequestStream();
                stream.Write(payload, 0, payload.Length);
                stream.Close();

                //Send Request
                System.Net.HttpWebResponse response = (System.Net.HttpWebResponse)request.GetResponse();

                //Output response to console
                System.IO.StreamReader reader = new System.IO.StreamReader(response.GetResponseStream());
                string responseBody = "";
                string temp = null;
                while ((temp = reader.ReadLine()) != null)
                {
                    responseBody += temp;
                };

                //json parsing variables - this will retrieve the meta and failure messages to confirm successful entries from Mimecast's API
                var jsonDoc = JsonDocument.Parse(responseBody);
                var root = jsonDoc.RootElement;
                var entrystatus = root.GetProperty("meta");
                var entryfailstatus = root.GetProperty("fail");

                //error handling and updating status if status is 200 and no failures this means the site was successfully added, if not it confirms status ok but there were failures
                if (entrystatus.ToString() == "{\"status\":200}")
                {
                    if (entryfailstatus.ToString() == "[]")
                    {
                        status.Text = ("URL added successfully.");
                    }
                    else
                    {
                        status.Text = ("Status OK but failures present!");
                    }
                }
                else
                {
                    status.Text = ("URL not blocked, status failed.");
                }
            }
        }
    }
}
