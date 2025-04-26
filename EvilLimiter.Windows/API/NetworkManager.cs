using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Threading;
using EvilLimiter.Windows.Data;
using EvilLimiter.Windows.Networking;
using EvilLimiter.Windows.Utilities;
using PcapDotNet.Core;
using PcapDotNet.Core.Extensions;
using PcapDotNet.Packets.Ethernet;
using PcapDotNet.Packets.IpV4;
using WinDivertSharp;

namespace EvilLimiter.Windows.API
{
    public class NetworkManager : IDisposable
    {
        private NetworkInformation _currentNetworkInfo;
        private HostSpoofer _hostSpoofer;
        private HostLimiter _hostLimiter;
        private bool _isInitialized = false;
        private readonly Dictionary<string, Host> _knownHosts = new Dictionary<string, Host>();
        private AggressiveHostScanner _currentScanner;
        private readonly object _scannerLock = new object();

        public NetworkManager()
        {
        }

        public bool IsInitialized => _isInitialized;

        public NetworkInformation InitializeNetworkInterface(LivePacketDevice device, DeviceAddress address)
        {
            // First, stop any ongoing scanning
            lock (_scannerLock)
            {
                if (_currentScanner != null && _currentScanner.IsScanning)
                {
                    _currentScanner.Cancel();
                    Thread.Sleep(1000); // Give time for the scan to stop
                }
            }

            // Then dispose current resources
            if (_currentNetworkInfo != null)
            {
                Dispose();
            }

            // Create new packet communicator
            var communicator = device.Open(100, PacketDeviceOpenAttributes.Promiscuous, 1000);

            // Get interface information
            var interfaceAddress = ((IpV4SocketAddress)address.Address).Address;
            var netmask = address.Netmask?.Family == SocketAddressFamily.Internet
                ? ((IpV4SocketAddress)address.Netmask).Address
                : new IpV4Address("255.255.255.0");

            // Assume gateway is .1 of the subnet
            string ipStr = interfaceAddress.ToString();
            string baseIp = ipStr.Substring(0, ipStr.LastIndexOf('.') + 1);
            var gatewayIp = new IpV4Address(baseIp + "1");

            // Try to get gateway MAC
            MacAddress gatewayMac;
            try
            {
                var macResult = NetworkUtilities.GetMacByIpAddress(device, communicator, interfaceAddress, gatewayIp, 3000);
                gatewayMac = macResult ?? new MacAddress("FF:FF:FF:FF:FF:FF");
            }
            catch
            {
                gatewayMac = new MacAddress("FF:FF:FF:FF:FF:FF");
            }

            // Get subnet range
            var subnetRange = NetworkUtilities.GetIpRange($"{interfaceAddress}/{netmask}");

            // Create WinDivert handle
            var winDivertHandle = WinDivert.WinDivertOpen("true", WinDivertLayer.Forward, 0, WinDivertOpenFlags.None);
            if (winDivertHandle == new IntPtr(-1))
            {
                throw new Exception($"WinDivert handle could not be opened. Error Code: {Marshal.GetLastWin32Error()}");
            }

            _currentNetworkInfo = new NetworkInformation
            {
                Interface = device,
                Communicator = communicator,
                InterfaceAddress = address,
                GatewayIp = gatewayIp,
                GatewayMac = gatewayMac,
                Netmask = netmask,
                SubnetRange = subnetRange,
                WinDivertHandle = winDivertHandle
            };

            // Initialize components
            _hostSpoofer = new HostSpoofer(_currentNetworkInfo);
            _hostSpoofer.Start();

            _hostLimiter = new HostLimiter(_currentNetworkInfo);
            _hostLimiter.Start();

            _isInitialized = true;
            return _currentNetworkInfo;
        }

        public List<Host> ScanHosts()
        {
            if (!_isInitialized)
            {
                throw new InvalidOperationException("Network interface not initialized. Call InitializeNetworkInterface first.");
            }

            // Cancel any existing scan
            lock (_scannerLock)
            {
                if (_currentScanner != null && _currentScanner.IsScanning)
                {
                    _currentScanner.Cancel();
                    Thread.Sleep(1000); // Give time for the previous scan to stop
                }
            }

            var hosts = new List<Host>();
            var scanCompleted = new ManualResetEvent(false);

            // Create a new scanner
            lock (_scannerLock)
            {
                _currentScanner = new AggressiveHostScanner(_currentNetworkInfo);
            }

            _currentScanner.ScanFinished += (sender, e) =>
            {
                if (e.Hosts != null)
                {
                    hosts.AddRange(e.Hosts);
                    foreach (var host in e.Hosts)
                    {
                        string key = $"{host.IpAddress}_{host.MacAddress}";
                        _knownHosts[key] = host;
                    }
                }
                scanCompleted.Set();
            };

            // Start scanning
            _currentScanner.Scan(_currentNetworkInfo.SubnetRange);

            // Wait for scan to complete
            bool completed = scanCompleted.WaitOne(90000); // 90 seconds timeout

            if (!completed)
            {
                Console.WriteLine("Scan timed out after 90 seconds");
            }
            else
            {
                Console.WriteLine($"Scan completed. Found {hosts.Count} hosts");
            }

            return hosts;
        }

        public bool BlockHost(string ipAddress, string macAddress)
        {
            try
            {
                if (!_isInitialized)
                {
                    throw new InvalidOperationException("Network interface not initialized");
                }

                // Create a host object
                var host = new Host(new IpV4Address(ipAddress), new MacAddress(macAddress));

                // Check if host exists in known hosts
                string key = $"{ipAddress}_{macAddress}";
                if (_knownHosts.ContainsKey(key))
                {
                    host = _knownHosts[key];
                }

                // Add to spoofer and limiter to block the host
                _hostSpoofer.Add(host);
                _hostLimiter.Add(host, LimitRule.Block);

                return true;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error blocking host: {ex.Message}");
                return false;
            }
        }

        public bool UnblockHost(string ipAddress, string macAddress)
        {
            try
            {
                if (!_isInitialized)
                {
                    throw new InvalidOperationException("Network interface not initialized");
                }

                // Create a host object
                var host = new Host(new IpV4Address(ipAddress), new MacAddress(macAddress));

                // Check if host exists in known hosts
                string key = $"{ipAddress}_{macAddress}";
                if (_knownHosts.ContainsKey(key))
                {
                    host = _knownHosts[key];
                }

                // Remove from spoofer and limiter
                _hostSpoofer.Remove(host);
                _hostLimiter.Remove(host);

                return true;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error unblocking host: {ex.Message}");
                return false;
            }
        }

        public void Dispose()
        {
            try
            {
                // First, cancel any ongoing scan
                lock (_scannerLock)
                {
                    if (_currentScanner != null && _currentScanner.IsScanning)
                    {
                        _currentScanner.Cancel();
                        Thread.Sleep(1000); // Give time for the scan to stop
                    }
                    _currentScanner = null;
                }

                _isInitialized = false;

                // Stop spoofer and limiter first
                if (_hostSpoofer != null)
                {
                    _hostSpoofer.Stop();
                    _hostSpoofer = null;
                }

                if (_hostLimiter != null)
                {
                    _hostLimiter.Stop();
                    _hostLimiter = null;
                }

                // Wait a bit to ensure all operations are stopped
                Thread.Sleep(500);

                // Now dispose of network resources
                if (_currentNetworkInfo != null)
                {
                    if (_currentNetworkInfo.WinDivertHandle != IntPtr.Zero)
                    {
                        WinDivert.WinDivertClose(_currentNetworkInfo.WinDivertHandle);
                    }

                    if (_currentNetworkInfo.Communicator != null)
                    {
                        _currentNetworkInfo.Communicator.Break(); // Break out of receive loop first
                        Thread.Sleep(100);
                        _currentNetworkInfo.Communicator.Dispose();
                    }

                    _currentNetworkInfo = null;
                }

                _knownHosts.Clear();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error during dispose: {ex.Message}");
            }
        }
    }
}