using EvilLimiter.Windows.Common;
using EvilLimiter.Windows.Data;
using EvilLimiter.Windows.Extensions;
using EvilLimiter.Windows.Utilities;
using PcapDotNet.Base;
using PcapDotNet.Core;
using PcapDotNet.Core.Extensions;
using PcapDotNet.Packets;
using PcapDotNet.Packets.Arp;
using PcapDotNet.Packets.Ethernet;
using PcapDotNet.Packets.IpV4;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace EvilLimiter.Windows.Networking
{
    public class AggressiveHostScanner
    {
        public bool IsScanning { get; private set; }

        private readonly NetworkInformation _networkInfo;
        private int _totalScans;
        private int _finishedScans;
        private CancellationTokenSource _tokenSource;

        #region Events
        public event EventHandler<ScanFinishedEventArgs> ScanFinished;
        private void OnScanFinished(ScanFinishedEventArgs e)
            => ScanFinished?.Invoke(this, e);

        public event EventHandler<HostScannedEventArgs> HostScanned;
        private void OnHostScanned(HostScannedEventArgs e)
            => HostScanned?.Invoke(this, e);
        #endregion

        public AggressiveHostScanner(NetworkInformation netInfo)
        {
            this._networkInfo = netInfo;
        }

        public void Scan(ICollection<IpV4Address> addresses)
        {
            if (IsScanning)
                return;

            IsScanning = true;
            _totalScans = addresses.Count;
            _finishedScans = 0;

            var sourceAddress = ((IpV4SocketAddress)_networkInfo.InterfaceAddress.Address).Address;
            var sourcePhysicalAddress = _networkInfo.Interface.GetNetworkInterface().GetPhysicalAddress();

            _tokenSource = new CancellationTokenSource();
            var cancellationToken = _tokenSource.Token;
            var discoveredHosts = new List<Host>();
            var discoveredHostsLock = new object();

            // Start receiver thread
            Task.Run(() =>
            {
                while (!cancellationToken.IsCancellationRequested)
                {
                    try
                    {
                        if (cancellationToken.IsCancellationRequested)
                            break;

                        _networkInfo.Communicator.ReceivePacket(out Packet p);

                        if (cancellationToken.IsCancellationRequested)
                            break;

                        if (p != null &&
                            p.IsValid &&
                            p.Ethernet.IsValid &&
                            p.Ethernet.EtherType == EthernetType.Arp &&
                            p.Ethernet.Arp.IsValid &&
                            p.Ethernet.Arp.Operation == ArpOperation.Reply &&
                            addresses.Contains(p.Ethernet.Arp.SenderProtocolIpV4Address) &&
                            p.Ethernet.Arp.TargetProtocolIpV4Address == sourceAddress)
                        {
                            var host = new Host(
                                p.Ethernet.Arp.SenderProtocolIpV4Address,
                                new MacAddress(BitConverter.ToString(p.Ethernet.Arp.SenderHardwareAddress.ToArray()).Replace('-', ':'))
                            );

                            lock (discoveredHostsLock)
                            {
                                if (!discoveredHosts.Contains(host))
                                {
                                    discoveredHosts.Add(host);
                                    Console.WriteLine($"Discovered: {host.IpAddress} - {host.MacAddress}");
                                }
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        if (!cancellationToken.IsCancellationRequested)
                        {
                            Console.WriteLine($"Error receiving packet: {ex.Message}");
                            Thread.Sleep(10);
                        }
                    }
                }
            }, cancellationToken);

            // Start sender thread with aggressive scanning
            Task.Run(() =>
            {
                const int scansPerIp = 5; // Number of ARP requests per IP
                const int scanDelay = 5; // Delay between individual scans in ms
                const int ipDelay = 20; // Delay between different IPs

                foreach (var addr in addresses)
                {
                    for (int i = 0; i < scansPerIp; i++)
                    {
                        var packet = PacketBuilder.Build(
                            DateTime.Now,
                            new EthernetLayer()
                            {
                                EtherType = EthernetType.None,
                                Source = NetworkUtilities.PhysicalAddressToMacAddress(sourcePhysicalAddress),
                                Destination = NetworkUtilities.BroadcastMac,
                            },
                            new ArpLayer()
                            {
                                ProtocolType = EthernetType.IpV4,
                                Operation = ArpOperation.Request,
                                SenderProtocolAddress = sourceAddress.ToBytes(),
                                SenderHardwareAddress = sourcePhysicalAddress.GetAddressBytes().AsReadOnly(),
                                TargetProtocolAddress = addr.ToBytes(),
                                TargetHardwareAddress = MacAddress.Zero.ToBytes(),
                            }
                        );

                        _networkInfo.Communicator.SendPacket(packet);

                        if (cancellationToken.IsCancellationRequested)
                            break;

                        Thread.Sleep(scanDelay);
                    }

                    if (cancellationToken.IsCancellationRequested)
                        break;

                    Interlocked.Increment(ref _finishedScans);
                    OnHostScanned(new HostScannedEventArgs(_totalScans, _finishedScans));

                    Thread.Sleep(ipDelay);
                }

                // Additional sweep for stubborn devices
                if (!cancellationToken.IsCancellationRequested)
                {
                    Console.WriteLine("Performing additional sweep...");
                    foreach (var addr in addresses)
                    {
                        var packet = PacketBuilder.Build(
                            DateTime.Now,
                            new EthernetLayer()
                            {
                                EtherType = EthernetType.None,
                                Source = NetworkUtilities.PhysicalAddressToMacAddress(sourcePhysicalAddress),
                                Destination = NetworkUtilities.BroadcastMac,
                            },
                            new ArpLayer()
                            {
                                ProtocolType = EthernetType.IpV4,
                                Operation = ArpOperation.Request,
                                SenderProtocolAddress = sourceAddress.ToBytes(),
                                SenderHardwareAddress = sourcePhysicalAddress.GetAddressBytes().AsReadOnly(),
                                TargetProtocolAddress = addr.ToBytes(),
                                TargetHardwareAddress = NetworkUtilities.BroadcastMac.ToBytes(), // Using broadcast MAC for extra coverage
                            }
                        );

                        _networkInfo.Communicator.SendPacket(packet);
                        Thread.Sleep(10);
                    }
                }

                if (!cancellationToken.IsCancellationRequested)
                {
                    Thread.Sleep(5000); // Wait 5 seconds for late responses
                    _tokenSource.Cancel();

                    // Resolve hostnames
                    foreach (var host in discoveredHosts)
                    {
                        try
                        {
                            host.HostName = NetworkUtilities.GetHostNameByIp(host.IpAddress);
                        }
                        catch
                        {
                            host.HostName = "Unknown";
                        }
                    }

                    OnScanFinished(new ScanFinishedEventArgs(discoveredHosts));
                }

                IsScanning = false;
            }, cancellationToken);
        }

        public void Cancel()
        {
            if (IsScanning && _tokenSource != null && !_tokenSource.IsCancellationRequested)
            {
                _totalScans = 0;
                _finishedScans = 0;
                _tokenSource.Cancel();

                // Break out of receive loop
                try
                {
                    _networkInfo.Communicator.Break();
                }
                catch
                {
                    // Ignore errors when breaking
                }

                IsScanning = false;
            }
        }
    }
}