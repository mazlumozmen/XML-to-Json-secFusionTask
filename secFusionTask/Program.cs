using Newtonsoft.Json;
using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.ServiceProcess;
using System.Text.Json;
using System.Web.Helpers;
using System.Xml;
using System.Xml.Linq;
using System.Net.Http;


namespace secFusion
{
    class Program
    {
        public class Info
        {
            public string scanName { get; set; }
            public string reportGenerated { get; set; }
            public IList<Hosts> hosts { get; set; }
        }
        public class Hosts
        {
            public string target { get; set; }
            public string scanStartDate { get; set; }
            public string scanFinishDate { get; set; }
            public string macAddress { get; set; }
            public string operatingSystem { get; set; }
            public IList<Vulnerabilities> vulnerabilities { get; set; }
        }
        public class Vulnerabilities
        {
            public string protocol { get; set; }
            public string severity { get; set; }
            public string pluginID { get; set; }
            public string name { get; set; }
            public float cvssBaseScore { get; set; }
            public string description { get; set; }
            public string solution { get; set; }
            public string output { get; set; }

        }
        public class Inputs
        {
            public string serverURL { get; set; }
            public string username { get; set; }
            public string password { get; set; }
        }

        public static string xmlFile = File.ReadAllText("secondtry.xml");
        public static XmlDocument xmldoc = new XmlDocument();
        static void Main(string[] args)
        {
            Console.WriteLine("Make sure you are running the application as an administrator.");

            /* Inputs inputs = new Inputs();
             Console.WriteLine("Nessus Server URL: ");
             inputs.serverURL = Console.ReadLine();
             Console.WriteLine("Username: ");
             inputs.username = Console.ReadLine();
             Console.WriteLine("Password: ");
             inputs.password = Console.ReadLine();*/



            xmldoc.LoadXml(xmlFile);
            getThings();
            writeFile();
            checkNessusService();
            Console.WriteLine("Json file has been created.");
            Console.ReadKey();
        }


        /// <summary>
        static HttpClient client = new HttpClient();
        public static void getScans()
        {
            client.BaseAddress = new Uri("https://localhost:8834/");

        }
        /// </summary>



        public static void checkNessusService()
        {
            ServiceController[] services = ServiceController.GetServices();
            foreach (ServiceController service in services)
            {
                if (service.ServiceName == "Tenable Nessus")
                {
                    if (service.Status!=ServiceControllerStatus.Running)
                    {
                            service.Start();
                            Console.WriteLine("The " + service.ServiceName + " service has been started.");
                            break;
                    }
                    else
                    {
                        Console.WriteLine("Service is working.");
                    }
                }
            }
        }

        static Info nesne3 = new Info();
        static Hosts nesne2 = new Hosts();
        public static void getThings()
        {

            XmlNodeList nodeList = xmldoc.GetElementsByTagName("tag");
            foreach (XmlNode node in nodeList)
            {
                if (node.Attributes["name"].Value == "host-ip")
                {
                    nesne2.target = node.InnerText;

                }
                else if (node.Attributes["name"].Value == "HOST_START")
                {
                    nesne2.scanStartDate = node.InnerText;

                }
                else if (node.Attributes["name"].Value == "HOST_END")
                {
                    nesne2.scanFinishDate = node.InnerText;

                }
                else if (node.Attributes["name"].Value == "operating-system")
                {
                    nesne2.operatingSystem = node.InnerText;

                }

            }
            nodeList = xmldoc.GetElementsByTagName("Report");
            foreach (XmlNode node in nodeList)
            {
                nesne3.scanName = node.Attributes["name"].Value;
            }

            nodeList = xmldoc.GetElementsByTagName("ReportItem");
            string attribute = string.Empty;

        }

        public static void writeFile()
        {

            string json = "";
            List<Info> data = new List<Info>();
            List<Hosts> data2 = new List<Hosts>();
            List<Vulnerabilities> data3 = new List<Vulnerabilities>();
            data.Add(new Info()
            {
                scanName = nesne3.scanName,
                reportGenerated = DateTime.Now.ToString(),
                hosts = data2,
            }); ;

            data2.Add(new Hosts()
            {
                target = nesne2.target,
                scanStartDate = nesne2.scanStartDate,
                scanFinishDate = nesne2.scanFinishDate,
                operatingSystem = nesne2.operatingSystem,
                vulnerabilities = data3,
            });

            XmlNodeList nodeList = xmldoc.GetElementsByTagName("ReportItem");
            foreach (XmlNode node in nodeList)
            {
                string durum,output="";
                float score = 1;
                if (node.SelectSingleNode("cvss_base_score")!=null)
                {
                    score = (float.Parse(node.SelectSingleNode("cvss_base_score").InnerText))/10;
                }
                if (node.SelectSingleNode("plugin_output") != null)
                {
                    output = node.SelectSingleNode("plugin_output").InnerText;
                }

                switch (node.Attributes["severity"].Value)
                {
                    case "0":
                        durum = "info";
                        break;
                    case "1":
                        durum = "low";
                        break;
                    case "2":
                        durum = "medium";
                        break;
                    case "3":
                        durum = "high";
                        break;
                    case "4":
                        durum = "critical";
                        break;
                    default:
                        durum = "info";
                        break;
                }

                data3.Add(new Vulnerabilities()
                {
                    protocol = node.Attributes["protocol"].Value,
                    severity = durum,
                    pluginID = node.Attributes["pluginID"].Value,
                    name = node.Attributes["pluginName"].Value,
                    cvssBaseScore = score,
                    description = node.SelectSingleNode("description").InnerText,
                    solution = node.SelectSingleNode("solution").InnerText,
                    output = output,

                });

            }

            json += JsonConvert.SerializeObject(data.ToArray(), Newtonsoft.Json.Formatting.Indented);
            File.WriteAllText("jsonFile.json", json);
        }
    }
}
