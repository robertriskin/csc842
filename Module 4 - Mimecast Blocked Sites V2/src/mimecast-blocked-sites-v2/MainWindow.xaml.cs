using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;

namespace Mimecast_Blocked-Sites-V2
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        public MainWindow()
        {
            InitializeComponent();
        }
        //Add blocked sites button - executes the addblocked sites function
        private void Button_Click(object sender, RoutedEventArgs e)
        {
            AddBlockedSite();
        }
        //Quit button - closes the application
        private void Button_Click_1(object sender, RoutedEventArgs e)
        {
            System.Windows.Application.Current.Shutdown();
        }
        //Function that is executed once button is clicked and goes through various checks and eventually adds the e-mail or domain to the blocked sites profile group in mimecast
        public void AddBlockedSite()
        {
            //Setup required variables - ENTER YOUR OWN HERE
            string baseUrl = "https://us-api.mimecast.com";
            string uri = "/api/directory/add-group-member";
            string accessKey = "enter your own here";
            string secretKey = "enter your own here";
            string appId = "enter your own here";
            string appKey = "enter your own here";
            string blockedsenderid = "enter your own here";

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
            if (rb_domain.IsChecked == true)
            {
                status.Content = ("Domain selected.");
                if (CheckDomain(tb_entry.Text))
                {
                    status.Content = ("Domain is valid.");

                    //Add request body
                    //Create and write data to stream
                    string postData = "{\"data\": [{\"id\": \""+blockedsenderid+"\",\"domain\": \""+tb_entry.Text+"\"}]}";

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
                            status.Content = ("Domain added successfully.");
                        }
                        else
                        {
                            status.Content = ("Status OK but failures present!");
                        }
                    }
                    else
                    {
                        status.Content = ("Domain not blocked, status failed.");
                    }
                }
                else
                {
                    status.Content = ("Domain is on free-email list, please recheck!");
                }
            }
            if (rb_email.IsChecked == true)
            {
               
                if (ValidateEmail(tb_entry.Text))
                {
                    status.Content = ("Valid e-mail");

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
                            status.Content = ("E-mail address added successfully.");
                        }
                        else
                        {
                            status.Content = ("Status OK but failures present!");
                        }
                    }
                    else
                    {
                        status.Content = ("E-mail address not blocked, status failed.");
                    }

                }
                else
                {
                    status.Content = ("E-mail address entered is not valid!");
                }
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
        //Check domain function - checks to see if domain entered is one of the free e-mail domains
        public bool CheckDomain(string entereddomain)
        {
            string[] freeemaildomains = {"aol.com", "articmail.com", "gmail.com", "outlook.com", "live.com", "hotmail.com", "protonmail.com", "yahoo.com", "zoho.com"};
            if (freeemaildomains.Contains(entereddomain))
            {
                return false;
            }
            else
            {
                return true;
            }
        }
    }
}
