using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Web.Script.Serialization;
using EvilLimiter.Windows.Data;
using EvilLimiter.Windows.Networking;
using PcapDotNet.Core;
using PcapDotNet.Core.Extensions;
using PcapDotNet.Packets.IpV4;
using System.Linq;
using EvilLimiter.Windows.Utilities;
using PcapDotNet.Packets.Ethernet;
using System.Runtime.InteropServices;
using WinDivertSharp;
using System.Net.Sockets;

namespace EvilLimiter.Windows.API
{
    public class ApiServer
    {
        private HttpListener _listener;
        private bool _isRunning;
        private NetworkManager _networkManager;
        private JavaScriptSerializer _serializer;
        private string _port = "8080";

        public ApiServer()
        {
            _listener = new HttpListener();
            _listener.Prefixes.Add($"http://localhost:{_port}/");
            _serializer = new JavaScriptSerializer();
            _networkManager = new NetworkManager();
        }

        public void StartServer()
        {
            _listener.Start();
            _isRunning = true;
            Console.WriteLine($"API Server started on port {_port}");
            Console.WriteLine("Available endpoints:");
            Console.WriteLine("GET  /api/interfaces - List all network interfaces");
            Console.WriteLine("POST /api/scan - Scan hosts on selected interface");
            Console.WriteLine("POST /api/block - Block a host");
            Console.WriteLine("POST /api/unblock - Unblock a host");

            Task.Run(() => HandleRequests());
            Console.WriteLine("Press Ctrl+C to exit...");

            // Keep the application running
            var exitEvent = new ManualResetEvent(false);
            Console.CancelKeyPress += (sender, eventArgs) => {
                eventArgs.Cancel = true;
                exitEvent.Set();
            };
            exitEvent.WaitOne();

            StopServer();
        }

        private void StopServer()
        {
            _isRunning = false;
            _listener.Stop();
            _networkManager.Dispose();
            Console.WriteLine("Server stopped.");
        }

        private async Task HandleRequests()
        {
            while (_isRunning)
            {
                try
                {
                    var context = await _listener.GetContextAsync();
                    ProcessRequest(context);
                }
                catch (Exception ex)
                {
                    if (_isRunning)
                    {
                        Console.WriteLine($"Error: {ex.Message}");
                    }
                }
            }
        }

        private void ProcessRequest(HttpListenerContext context)
        {
            string path = context.Request.Url.AbsolutePath.ToLower();
            string method = context.Request.HttpMethod;

            try
            {
                switch (path)
                {
                    case "/api/interfaces":
                        if (method == "GET")
                            HandleGetInterfaces(context);
                        break;
                    case "/api/scan":
                        if (method == "POST")
                            HandleScanHosts(context);
                        break;
                    case "/api/block":
                        if (method == "POST")
                            HandleBlockHost(context);
                        break;
                    case "/api/unblock":
                        if (method == "POST")
                            HandleUnblockHost(context);
                        break;
                    default:
                        SendResponse(context, 404, new { error = "Endpoint not found" });
                        break;
                }
            }
            catch (Exception ex)
            {
                SendResponse(context, 500, new { error = ex.Message });
            }
        }

        private void HandleGetInterfaces(HttpListenerContext context)
        {
            var interfaces = new List<object>();

            foreach (var iface in LivePacketDevice.AllLocalMachine)
            {
                if (string.IsNullOrEmpty(iface.Description))
                    continue;

                foreach (var address in iface.Addresses)
                {
                    if (address?.Address?.Family == SocketAddressFamily.Internet)
                    {
                        var ipv4Address = ((IpV4SocketAddress)address.Address).Address;
                        var netmask = address.Netmask?.Family == SocketAddressFamily.Internet
                            ? ((IpV4SocketAddress)address.Netmask).Address.ToString()
                            : "255.255.255.0";

                        interfaces.Add(new
                        {
                            id = interfaces.Count,
                            name = iface.Name,
                            description = iface.Description,
                            ipAddress = ipv4Address.ToString(),
                            netmask = netmask,
                            type = iface.Attributes.ToString()
                            // Removed the 'flags' property as it doesn't exist
                        });
                    }
                }
            }

            SendResponse(context, 200, new { interfaces });
        }

        private void HandleScanHosts(HttpListenerContext context)
        {
            try
            {
                var requestData = ReadRequestBody(context);

                if (!requestData.ContainsKey("interfaceId"))
                {
                    SendResponse(context, 400, new { error = "interfaceId is required" });
                    return;
                }

                int interfaceId = Convert.ToInt32(requestData["interfaceId"]);
                Console.WriteLine($"Scanning interface ID: {interfaceId}");

                // Get the selected interface
                var interfaces = LivePacketDevice.AllLocalMachine.ToList();
                int currentIndex = 0;
                LivePacketDevice selectedInterface = null;
                DeviceAddress selectedAddress = null;

                foreach (var iface in interfaces)
                {
                    if (string.IsNullOrEmpty(iface.Description))
                        continue;

                    foreach (var address in iface.Addresses)
                    {
                        if (address?.Address?.Family == SocketAddressFamily.Internet)
                        {
                            if (currentIndex == interfaceId)
                            {
                                selectedInterface = iface;
                                selectedAddress = address;
                                break;
                            }
                            currentIndex++;
                        }
                    }
                    if (selectedAddress != null) break;
                }

                if (selectedInterface == null)
                {
                    SendResponse(context, 400, new { error = "Invalid interface ID" });
                    return;
                }

                Console.WriteLine($"Selected interface: {selectedInterface.Description}");
                Console.WriteLine($"Interface address: {((IpV4SocketAddress)selectedAddress.Address).Address}");

                // Initialize network information
                var networkInfo = _networkManager.InitializeNetworkInterface(selectedInterface, selectedAddress);
                Console.WriteLine($"Network initialized. Gateway: {networkInfo.GatewayIp}, Subnet range count: {networkInfo.SubnetRange.Count}");

                // Start scanning
                Console.WriteLine("Starting scan...");
                var scanResults = _networkManager.ScanHosts(networkInfo);
                Console.WriteLine($"Scan completed. Found {scanResults.Count} hosts");

                // Convert results to response format
                var hosts = scanResults.Select(host => new
                {
                    ipAddress = host.IpAddress.ToString(),
                    macAddress = host.MacAddress.ToString(),
                    hostName = host.HostName ?? "Unknown",
                    status = host.Status.ToString()
                }).ToList();

                SendResponse(context, 200, new { hosts });
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error in HandleScanHosts: {ex.Message}");
                Console.WriteLine($"Stack trace: {ex.StackTrace}");
                SendResponse(context, 500, new { error = ex.Message, stackTrace = ex.StackTrace });
            }
        }

        private void HandleBlockHost(HttpListenerContext context)
        {
            var requestData = ReadRequestBody(context);

            if (!requestData.ContainsKey("ipAddress") || !requestData.ContainsKey("macAddress"))
            {
                SendResponse(context, 400, new { error = "ipAddress and macAddress are required" });
                return;
            }

            string ipAddress = requestData["ipAddress"].ToString();
            string macAddress = requestData["macAddress"].ToString();

            // Create a host object
            var host = new Host(new IpV4Address(ipAddress), new MacAddress(macAddress));

            // Block the host
            bool success = _networkManager.BlockHost(host);

            SendResponse(context, 200, new { success });
        }

        private void HandleUnblockHost(HttpListenerContext context)
        {
            var requestData = ReadRequestBody(context);

            if (!requestData.ContainsKey("ipAddress") || !requestData.ContainsKey("macAddress"))
            {
                SendResponse(context, 400, new { error = "ipAddress and macAddress are required" });
                return;
            }

            string ipAddress = requestData["ipAddress"].ToString();
            string macAddress = requestData["macAddress"].ToString();

            // Create a host object
            var host = new Host(new IpV4Address(ipAddress), new MacAddress(macAddress));

            // Unblock the host
            bool success = _networkManager.UnblockHost(host);

            SendResponse(context, 200, new { success });
        }

        private Dictionary<string, object> ReadRequestBody(HttpListenerContext context)
        {
            using (var reader = new StreamReader(context.Request.InputStream, context.Request.ContentEncoding))
            {
                string body = reader.ReadToEnd();
                return _serializer.Deserialize<Dictionary<string, object>>(body);
            }
        }

        private void SendResponse(HttpListenerContext context, int statusCode, object data)
        {
            context.Response.StatusCode = statusCode;
            context.Response.ContentType = "application/json";

            string jsonResponse = _serializer.Serialize(data);
            byte[] buffer = Encoding.UTF8.GetBytes(jsonResponse);

            context.Response.ContentLength64 = buffer.Length;
            context.Response.OutputStream.Write(buffer, 0, buffer.Length);
            context.Response.OutputStream.Close();
        }
    }
}