using System;
using System.Net;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Collections.Generic;
using Newtonsoft.Json;
using System.Linq;

namespace EvilLimiter.Windows
{
    public class HttpServer
    {
        private readonly HttpListener _listener;
        private readonly string _baseUrl;
        private bool _isRunning;
        private CancellationTokenSource _cancellationTokenSource;

        // Store the initialized NetworkInformation
        private Data.NetworkInformation _networkInfo;

        // Store references to main components
        private Networking.HostScanner _hostScanner;
        private Networking.HostSpoofer _hostSpoofer;
        private Networking.HostLimiter _hostLimiter;

        // Store discovered hosts
        private List<Data.Host> _hosts = new List<Data.Host>();

        public HttpServer(string url = "http://localhost:8080/")
        {
            _baseUrl = url;
            _listener = new HttpListener();
            _listener.Prefixes.Add(_baseUrl);
        }

        public void Start()
        {
            if (_isRunning) return;

            _listener.Start();
            _isRunning = true;
            _cancellationTokenSource = new CancellationTokenSource();

            Console.WriteLine($"EvilLimiter API server started at {_baseUrl}");

            Task.Run(() => ListenLoop(_cancellationTokenSource.Token));
        }

        public void Stop()
        {
            if (!_isRunning) return;

            _cancellationTokenSource.Cancel();
            _listener.Stop();
            _isRunning = false;

            // Cleanup components
            _hostLimiter?.Stop();
            _hostSpoofer?.Stop();

            Console.WriteLine("EvilLimiter API server stopped");
        }

        private async Task ListenLoop(CancellationToken cancellationToken)
        {
            while (_isRunning && !cancellationToken.IsCancellationRequested)
            {
                try
                {
                    var context = await _listener.GetContextAsync();

                    // Process the request in a separate task so we can keep listening
                    Task.Run(() => ProcessRequest(context));
                }
                catch (Exception ex) when (!cancellationToken.IsCancellationRequested)
                {
                    Console.WriteLine($"Error in HTTP listener: {ex.Message}");
                }
            }
        }

        private async Task ProcessRequest(HttpListenerContext context)
        {
            try
            {
                var request = context.Request;
                var response = context.Response;

                // Set CORS headers for web access
                response.Headers.Add("Access-Control-Allow-Origin", "*");
                response.Headers.Add("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
                response.Headers.Add("Access-Control-Allow-Headers", "Content-Type, Accept");

                // Handle OPTIONS requests for CORS preflight
                if (request.HttpMethod == "OPTIONS")
                {
                    response.StatusCode = 200;
                    response.Close();
                    return;
                }

                // Route the request based on the URL and method
                string responseText = RouteRequest(request);

                // Send the response
                byte[] buffer = Encoding.UTF8.GetBytes(responseText);
                response.ContentLength64 = buffer.Length;
                response.ContentType = "application/json";
                await response.OutputStream.WriteAsync(buffer, 0, buffer.Length);
                response.Close();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error processing request: {ex.Message}");
                try
                {
                    context.Response.StatusCode = 500;
                    context.Response.Close();
                }
                catch { /* Ignore errors in error handling */ }
            }
        }

        private string RouteRequest(HttpListenerRequest request)
        {
            string path = request.Url.AbsolutePath.TrimEnd('/');
            string method = request.HttpMethod;

            // Handle routes
            if (path == "/api/interfaces" && method == "GET")
                return GetNetworkInterfaces();
            else if (path == "/api/interfaces" && method == "POST")
                return InitializeNetworkInterface(request);
            else if (path == "/api/scan" && method == "POST")
                return ScanHosts(request);
            else if (path == "/api/hosts" && method == "GET")
                return GetHosts();
            else if (path == "/api/hosts/limit" && method == "POST")
                return LimitHosts(request);
            else if (path == "/api/hosts/block" && method == "POST")
                return BlockHosts(request);
            else if (path == "/api/hosts/free" && method == "POST")
                return FreeHosts(request);

            // Default response for unknown routes
            return JsonConvert.SerializeObject(new { error = "Route not found" });
        }

        // API endpoint implementations
        // We'll implement these methods next


    private string GetNetworkInterfaces()
        {
            try
            {
                var interfaces = new List<object>();
                int interfaceIndex = 0;

                foreach (var iface in PcapDotNet.Core.LivePacketDevice.AllLocalMachine)
                {
                    if (string.IsNullOrEmpty(iface.Description))
                        continue;

                    foreach (var address in iface.Addresses)
                    {
                        if (address?.Address?.Family == PcapDotNet.Core.SocketAddressFamily.Internet)
                        {
                            var ipv4Address = ((PcapDotNet.Core.IpV4SocketAddress)address.Address).Address;

                            interfaces.Add(new
                            {
                                id = interfaceIndex++,
                                description = iface.Description,
                                address = ipv4Address.ToString()
                            });
                        }
                    }
                }

                return JsonConvert.SerializeObject(new { interfaces });
            }
            catch (Exception ex)
            {
                return JsonConvert.SerializeObject(new { error = ex.Message });
            }
        }

        private string InitializeNetworkInterface(HttpListenerRequest request)
        {
            try
            {
                using (var reader = new System.IO.StreamReader(request.InputStream, request.ContentEncoding))
                {
                    string requestBody = reader.ReadToEnd();
                    dynamic data = JsonConvert.DeserializeObject(requestBody);

                    // Get the selected interface index
                    int selectedIndex = data.interfaceIndex;

                    // Get gateway information from the request
                    string gatewayIp = data.gatewayIp;
                    string gatewayMac = data.gatewayMac;
                    string netmask = data.netmask;

                    // Get the interfaces
                    var devices = PcapDotNet.Core.LivePacketDevice.AllLocalMachine;

                    // Find the selected interface
                    int index = 0;
                    PcapDotNet.Core.LivePacketDevice selectedInterface = null;
                    PcapDotNet.Core.DeviceAddress selectedAddress = null;

                    foreach (var iface in devices)
                    {
                        if (string.IsNullOrEmpty(iface.Description))
                            continue;

                        foreach (var address in iface.Addresses)
                        {
                            if (address?.Address?.Family == PcapDotNet.Core.SocketAddressFamily.Internet)
                            {
                                if (index == selectedIndex)
                                {
                                    selectedInterface = iface;
                                    selectedAddress = address;
                                    break;
                                }
                                index++;
                            }
                        }

                        if (selectedInterface != null)
                            break;
                    }

                    if (selectedInterface == null)
                        return JsonConvert.SerializeObject(new { error = "Selected interface not found" });

                    // Initialize network components
                    InitializeNetworkComponents(selectedInterface, selectedAddress, gatewayIp, gatewayMac, netmask);

                    return JsonConvert.SerializeObject(new { success = true });
                }
            }
            catch (Exception ex)
            {
                return JsonConvert.SerializeObject(new { error = ex.Message });
            }
        }

        private void InitializeNetworkComponents(
            PcapDotNet.Core.LivePacketDevice iface,
            PcapDotNet.Core.DeviceAddress address,
            string gatewayIp,
            string gatewayMac,
            string netmask)
        {
            try
            {
                // Open a packet communicator
                var communicator = iface.Open(100,
                                           PcapDotNet.Core.PacketDeviceOpenAttributes.Promiscuous,
                                           1000);

                // Create network information
                var interfaceAddress = ((PcapDotNet.Core.IpV4SocketAddress)address.Address).Address;
                var gateway = new PcapDotNet.Packets.IpV4.IpV4Address(gatewayIp);
                var mac = new PcapDotNet.Packets.Ethernet.MacAddress(gatewayMac);
                var mask = new PcapDotNet.Packets.IpV4.IpV4Address(netmask);
                var subnetRange = Utilities.NetworkUtilities.GetIpRange($"{gatewayIp}/{netmask}");

                // Get WinDivert handle
                var winDivertHandle = WinDivertSharp.WinDivert.WinDivertOpen(
                    "true",
                    WinDivertSharp.WinDivertLayer.Forward,
                    0,
                    WinDivertSharp.WinDivertOpenFlags.None);

                if (winDivertHandle == new IntPtr(-1))
                    throw new Exception($"WinDivert handle could not be opened. Error Code: {System.Runtime.InteropServices.Marshal.GetLastWin32Error()}");

                _networkInfo = new Data.NetworkInformation
                {
                    Interface = iface,
                    Communicator = communicator,
                    InterfaceAddress = address,
                    GatewayIp = gateway,
                    GatewayMac = mac,
                    Netmask = mask,
                    SubnetRange = subnetRange,
                    WinDivertHandle = winDivertHandle
                };

                // Initialize components
                _hostScanner = new Networking.HostScanner(_networkInfo);
                _hostScanner.ScanFinished += HostScanner_ScanFinished;

                _hostSpoofer = new Networking.HostSpoofer(_networkInfo);
                _hostSpoofer.Start();

                _hostLimiter = new Networking.HostLimiter(_networkInfo);
                _hostLimiter.Start();

                Console.WriteLine("Network components initialized successfully");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error initializing network components: {ex.Message}");
                throw;
            }
        }

        private void HostScanner_ScanFinished(object sender, Networking.ScanFinishedEventArgs e)
        {
            // Add discovered hosts to our list
            lock (_hosts)
            {
                foreach (var host in e.Hosts)
                {
                    if (!_hosts.Contains(host))
                        _hosts.Add(host);
                }
            }

            Console.WriteLine($"Scan finished, found {e.Hosts.Count} hosts");
        }


        private string ScanHosts(HttpListenerRequest request)
        {
            try
            {
                if (_networkInfo == null)
                    return JsonConvert.SerializeObject(new { error = "Network interface not initialized" });

                using (var reader = new System.IO.StreamReader(request.InputStream, request.ContentEncoding))
                {
                    string requestBody = reader.ReadToEnd();
                    dynamic data = JsonConvert.DeserializeObject(requestBody);

                    // Determine scan range - either entire subnet or custom range
                    bool useEntireSubnet = data.entireSubnet ?? true;
                    string customRange = data.customRange;

                    List<PcapDotNet.Packets.IpV4.IpV4Address> scanRange;

                    if (useEntireSubnet)
                    {
                        scanRange = _networkInfo.SubnetRange;
                    }
                    else
                    {
                        scanRange = Utilities.NetworkUtilities.GetIpRange(customRange);
                    }

                    // Start the scan
                    _hostScanner.Scan(scanRange);

                    return JsonConvert.SerializeObject(new { success = true, message = "Scan started" });
                }
            }
            catch (Exception ex)
            {
                return JsonConvert.SerializeObject(new { error = ex.Message });
            }
        }

        private string GetHosts()
        {
            try
            {
                if (_networkInfo == null)
                    return JsonConvert.SerializeObject(new { error = "Network interface not initialized" });

                var hostsList = new List<object>();

                lock (_hosts)
                {
                    foreach (var host in _hosts)
                    {
                        hostsList.Add(new
                        {
                            ip = host.IpAddress.ToString(),
                            mac = host.MacAddress.ToString(),
                            hostname = host.HostName,
                            status = host.Status.ToString(),
                            uploadStatus = host.UploadStatus,
                            downloadStatus = host.DownloadStatus
                        });
                    }
                }

                return JsonConvert.SerializeObject(new { hosts = hostsList });
            }
            catch (Exception ex)
            {
                return JsonConvert.SerializeObject(new { error = ex.Message });
            }
        }

        private string LimitHosts(HttpListenerRequest request)
        {
            try
            {
                if (_networkInfo == null)
                    return JsonConvert.SerializeObject(new { error = "Network interface not initialized" });

                using (var reader = new System.IO.StreamReader(request.InputStream, request.ContentEncoding))
                {
                    string requestBody = reader.ReadToEnd();
                    dynamic data = JsonConvert.DeserializeObject(requestBody);

                    // Get hosts to limit
                    string[] hostIps = data.hosts.ToObject<string[]>();

                    // Get limit rules
                    bool limitUpload = data.limitUpload;
                    long? uploadRate = data.uploadRate;
                    Data.BitByteUnit uploadUnit = (Data.BitByteUnit)Enum.Parse(typeof(Data.BitByteUnit), data.uploadUnit);
                    long? uploadBurst = data.uploadBurst;

                    bool limitDownload = data.limitDownload;
                    long? downloadRate = data.downloadRate;
                    Data.BitByteUnit downloadUnit = (Data.BitByteUnit)Enum.Parse(typeof(Data.BitByteUnit), data.downloadUnit);
                    long? downloadBurst = data.downloadBurst;

                    // Create limit rule
                    var rule = new Data.LimitRule();

                    if (limitUpload)
                    {
                        rule.UploadRate = Utilities.NetworkUtilities.BrokenDownRateToBitRate(uploadRate.Value, uploadUnit);
                        if (uploadBurst.HasValue)
                            rule.UploadBurst = Utilities.NetworkUtilities.BrokenDownRateToBitRate(uploadBurst.Value, uploadUnit);
                    }

                    if (limitDownload)
                    {
                        rule.DownloadRate = Utilities.NetworkUtilities.BrokenDownRateToBitRate(downloadRate.Value, downloadUnit);
                        if (downloadBurst.HasValue)
                            rule.DownloadBurst = Utilities.NetworkUtilities.BrokenDownRateToBitRate(downloadBurst.Value, downloadUnit);
                    }

                    // Apply the limit to selected hosts
                    List<Data.Host> limitedHosts = new List<Data.Host>();
                    lock (_hosts)
                    {
                        foreach (var host in _hosts)
                        {
                            if (hostIps.Contains(host.IpAddress.ToString()))
                            {
                                _hostSpoofer.Add(host);
                                _hostLimiter.Add(host, rule);
                                limitedHosts.Add(host);
                            }
                        }
                    }

                    return JsonConvert.SerializeObject(new
                    {
                        success = true,
                        message = $"Applied limit to {limitedHosts.Count} hosts"
                    });
                }
            }
            catch (Exception ex)
            {
                return JsonConvert.SerializeObject(new { error = ex.Message });
            }
        }

        private string BlockHosts(HttpListenerRequest request)
        {
            try
            {
                if (_networkInfo == null)
                    return JsonConvert.SerializeObject(new { error = "Network interface not initialized" });

                using (var reader = new System.IO.StreamReader(request.InputStream, request.ContentEncoding))
                {
                    string requestBody = reader.ReadToEnd();
                    dynamic data = JsonConvert.DeserializeObject(requestBody);

                    // Get hosts to block
                    string[] hostIps = data.hosts.ToObject<string[]>();

                    // Block selected hosts
                    int blockedCount = 0;
                    lock (_hosts)
                    {
                        foreach (var host in _hosts)
                        {
                            if (hostIps.Contains(host.IpAddress.ToString()))
                            {
                                _hostSpoofer.Add(host);
                                _hostLimiter.Add(host, Data.LimitRule.Block);
                                blockedCount++;
                            }
                        }
                    }

                    return JsonConvert.SerializeObject(new
                    {
                        success = true,
                        message = $"Blocked {blockedCount} hosts"
                    });
                }
            }
            catch (Exception ex)
            {
                return JsonConvert.SerializeObject(new { error = ex.Message });
            }
        }

        private string FreeHosts(HttpListenerRequest request)
        {
            try
            {
                if (_networkInfo == null)
                    return JsonConvert.SerializeObject(new { error = "Network interface not initialized" });

                using (var reader = new System.IO.StreamReader(request.InputStream, request.ContentEncoding))
                {
                    string requestBody = reader.ReadToEnd();
                    dynamic data = JsonConvert.DeserializeObject(requestBody);

                    // Get hosts to free
                    string[] hostIps = data.hosts.ToObject<string[]>();

                    // Free selected hosts
                    int freedCount = 0;
                    lock (_hosts)
                    {
                        foreach (var host in _hosts)
                        {
                            if (hostIps.Contains(host.IpAddress.ToString()))
                            {
                                _hostSpoofer.Remove(host);
                                _hostLimiter.Remove(host);
                                freedCount++;
                            }
                        }
                    }

                    return JsonConvert.SerializeObject(new
                    {
                        success = true,
                        message = $"Freed {freedCount} hosts"
                    });
                }
            }
            catch (Exception ex)
            {
                return JsonConvert.SerializeObject(new { error = ex.Message });
            }
        }
    }
}