// API/NetworkManager.cs
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
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
        private HostScanner _hostScanner;

        public NetworkManager()
        {
        }

        public NetworkInformation InitializeNetworkInterface(LivePacketDevice device, DeviceAddress address)
        {
            if (_currentNetworkInfo != null)
            {
                Dispose();
            }

            // Create packet communicator
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

            return _currentNetworkInfo;
        }

        public List<Host> ScanHosts(NetworkInformation networkInfo)
        {
            var hosts = new List<Host>();
            var scanCompleted = new ManualResetEvent(false);

            // Create a new scanner for each scan
            var scanner = new HostScanner(networkInfo);

            scanner.ScanFinished += (sender, e) =>
            {
                if (e.Hosts != null)
                {
                    hosts.AddRange(e.Hosts);
                }
                scanCompleted.Set();
            };

            // Start scanning
            scanner.Scan(networkInfo.SubnetRange);

            // Wait for scan to complete
            bool completed = scanCompleted.WaitOne(65000); // 60 seconds timeout

            if (!completed)
            {
                Console.WriteLine("Scan timed out after 30 seconds");
            }
            else
            {
                Console.WriteLine($"Scan completed. Found {hosts.Count} hosts");
            }

            return hosts;
        }

        public bool BlockHost(Host host)
        {
            try
            {
                if (_hostSpoofer == null || _hostLimiter == null)
                {
                    throw new InvalidOperationException("Network components not initialized");
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

        public bool UnblockHost(Host host)
        {
            try
            {
                if (_hostSpoofer == null || _hostLimiter == null)
                {
                    throw new InvalidOperationException("Network components not initialized");
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

                if (_currentNetworkInfo != null)
                {
                    if (_currentNetworkInfo.WinDivertHandle != IntPtr.Zero)
                    {
                        WinDivert.WinDivertClose(_currentNetworkInfo.WinDivertHandle);
                    }

                    if (_currentNetworkInfo.Communicator != null)
                    {
                        _currentNetworkInfo.Communicator.Dispose();
                    }

                    _currentNetworkInfo = null;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error during dispose: {ex.Message}");
            }
        }
    }
}