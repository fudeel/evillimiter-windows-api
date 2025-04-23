using EvilLimiter.Windows.Common;
using EvilLimiter.Windows.Data;
using EvilLimiter.Windows.Utilities;
using MetroFramework;
using PcapDotNet.Core;
using PcapDotNet.Core.Extensions;
using PcapDotNet.Packets.Ethernet;
using PcapDotNet.Packets.IpV4;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Threading.Tasks;
using System.Windows.Forms;
using WinDivertSharp;

namespace EvilLimiter.Windows.Forms
{
    public partial class FrmInterface : FrmBase
    {
        private readonly Dictionary<LivePacketDevice, DeviceAddress> _interfaces;
        private LivePacketDevice _currentInterface;
        private PacketCommunicator _packetCommunicator;



        public FrmInterface()
        {
            InitializeComponent();

            this._interfaces = new Dictionary<LivePacketDevice, DeviceAddress>();

            InitializeInterfaces();
        }



        private void InitializeInterfaces()
        {
            try
            {
                _interfaces.Clear();
                cbInterfaces.Items.Clear();

                int interfaceIndex = 0;
                foreach (var iface in LivePacketDevice.AllLocalMachine)
                {
                    if (string.IsNullOrEmpty(iface.Description))
                        continue;

                    foreach (var address in iface.Addresses)
                    {
                        if (address?.Address?.Family == SocketAddressFamily.Internet)
                        {
                            // Use a direct identifier for the interface that doesn't rely on GetNetworkInterface
                            string displayName;
                            try
                            {
                                // Try to use description
                                displayName = $"{iface.Description} - {address.Address}";
                                interfaceIndex++;
                            }
                            catch
                            {
                                // Fallback to a simple numbered interface
                                displayName = $"Interface {interfaceIndex} - {address.Address}";
                                interfaceIndex++;
                            }

                            // Add to dictionary and combobox
                            _interfaces.Add(iface, address);
                            cbInterfaces.Items.Add(displayName);
                        }
                    }
                }

                if (_interfaces.Count > 0)
                    cbInterfaces.SelectedIndex = 0;
                else
                {
                    MetroMessageBox.Show(this, "No network interface detected.", "Interface Error", MessageBoxButtons.OK, MessageBoxIcon.Error, 120);
                    Environment.Exit(-1);
                }
            }
            catch (Exception ex)
            {
                MetroMessageBox.Show(this,
                    $"Error initializing network interfaces: {ex.Message}\nStack trace: {ex.StackTrace}",
                    "Interface Error",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Error,
                    120);
                Environment.Exit(-1);
            }
        }


        private void ShowStatus(string status)
        {
            lblStatus.Text = status;
            lblStatus.Visible = true;
            spinStatus.Visible = true;
        }


        private void HideStatus()
        {
            lblStatus.Visible = false;
            spinStatus.Visible = false;
        }


        private NetworkInformation ParseNetworkInformation()
        {
            var errorMessage = new Action<string, string>((title, msg) => MetroMessageBox.Show(this, msg, title, MessageBoxButtons.OK, MessageBoxIcon.Error, 120));

            IpV4Address gatewayIp;
            MacAddress gatewayMac;
            IpV4Address netmask;
            List<IpV4Address> subnetRange;
            IntPtr winDivertHandle;

            if (_currentInterface == null)
            {
                errorMessage("Interface Error", "No network interface selected.");
                return null;
            }

            try
            {
                gatewayIp = new IpV4Address(tbGatewayIp.Text);
            }
            catch (Exception)
            {
                errorMessage("Value Error", "Invalid gateway IP.");
                return null;
            }

            try
            {
                gatewayMac = new MacAddress(tbGatewayMac.Text);
            }
            catch (Exception)
            {
                errorMessage("Value Error", "Invalid gateway MAC.");
                return null;
            }

            try
            {
                netmask = new IpV4Address(tbNetmask.Text);
            }
            catch (Exception)
            {
                errorMessage("Value Error", "Invalid netmask.");
                return null;
            }

            try
            {
                subnetRange = NetworkUtilities.GetIpRange(string.Format("{0}/{1}", gatewayIp.ToString(), netmask.ToString()));
            }
            catch (Exception)
            {
                errorMessage("Value Error", "Invalid netmask.");
                return null;
            }

            winDivertHandle = WinDivert.WinDivertOpen("true", WinDivertLayer.Forward, 0, WinDivertOpenFlags.None);
            if (winDivertHandle == new IntPtr(-1))
            {
                errorMessage("WinDivert Error", string.Format("WinDivert handle could not be opened.\nError Code: {0}", Marshal.GetLastWin32Error()));
                return null;
            }

            return new NetworkInformation()
            {
                Interface = _currentInterface,
                Communicator = _packetCommunicator,
                InterfaceAddress = _interfaces[_currentInterface],
                GatewayIp = gatewayIp,
                GatewayMac = gatewayMac,
                Netmask = netmask,
                SubnetRange = subnetRange,
                WinDivertHandle = winDivertHandle,
            };
        }


        #region Form Events

        private void CbInterfaces_SelectedIndexChanged(object sender, EventArgs e)
        {
            try
            {
                tbGatewayIp.Clear();
                tbGatewayMac.Clear();
                tbNetmask.Clear();

                if (cbInterfaces.SelectedIndex < 0)
                    return;

                // Dispose of existing communicator
                if (_packetCommunicator != null)
                {
                    _packetCommunicator.Dispose();
                    _packetCommunicator = null;
                }

                // Get the selected interface by index
                var selectedIndex = cbInterfaces.SelectedIndex;
                if (selectedIndex >= _interfaces.Count)
                {
                    MetroMessageBox.Show(this, "Invalid interface selection.", "Interface Error",
                        MessageBoxButtons.OK, MessageBoxIcon.Error, 120);
                    return;
                }

                var iface = _interfaces.Keys.ElementAt(selectedIndex);

                try
                {
                    // Open a packet communicator
                    _packetCommunicator = iface.Open(100, // 100ms read timeout
                                                   PacketDeviceOpenAttributes.Promiscuous, // promiscuous mode
                                                   1000); // 1000ms read timeout
                }
                catch (Exception ex)
                {
                    MetroMessageBox.Show(this, $"Failed to open interface: {ex.Message}",
                        "Interface Error", MessageBoxButtons.OK, MessageBoxIcon.Error, 120);
                    return;
                }

                if (_packetCommunicator == null)
                {
                    MetroMessageBox.Show(this, "Failed to create packet communicator.",
                        "Interface Error", MessageBoxButtons.OK, MessageBoxIcon.Error, 120);
                    return;
                }

                _currentInterface = iface;
                var address = _interfaces[iface];

                // Update the interface address display
                UpdateAddressesWithoutNetworkInterface(iface, address);
            }
            catch (Exception ex)
            {
                MetroMessageBox.Show(this, $"Error selecting interface: {ex.Message}",
                    "Interface Error", MessageBoxButtons.OK, MessageBoxIcon.Error, 120);
            }
        }

        private void UpdateAddressesWithoutNetworkInterface(LivePacketDevice iface, DeviceAddress address)
        {
            try
            {
                // Update interface address label
                var interfaceAddress = ((IpV4SocketAddress)address.Address).Address;
                lblInterfaceAddress.Text = interfaceAddress.ToString();

                // Update netmask if available
                if (address.Netmask?.Family == SocketAddressFamily.Internet)
                {
                    tbNetmask.Text = ((IpV4SocketAddress)address.Netmask).Address.ToString();
                }
                else
                {
                    // Default netmask for class C network
                    tbNetmask.Text = "255.255.255.0";
                }

                // Try to determine gateway - use common gateway addresses
                string[] commonGateways = { "192.168.1.1", "192.168.0.1", "10.0.0.1" };
                string ipStr = interfaceAddress.ToString();
                string baseIp = ipStr.Substring(0, ipStr.LastIndexOf('.') + 1);
                string possibleGateway = baseIp + "1"; // Assume gateway is .1

                tbGatewayIp.Text = possibleGateway;

                // Show status and try to resolve MAC
                ShowStatus("resolving MAC address...");
                cbInterfaces.Enabled = false;

                Task.Run(() =>
                {
                    try
                    {
                        var macAddress = NetworkUtilities.GetMacByIpAddress(iface,
                            _packetCommunicator,
                            interfaceAddress,
                            new IpV4Address(possibleGateway),
                            3000);

                        Invoke((MethodInvoker)delegate
                        {
                            if (macAddress != null)
                            {
                                tbGatewayMac.Text = macAddress.ToString();
                            }
                            else
                            {
                                // If we couldn't resolve, use a default MAC
                                tbGatewayMac.Text = "FF:FF:FF:FF:FF:FF";
                            }

                            HideStatus();
                            cbInterfaces.Enabled = true;
                        });
                    }
                    catch (Exception ex)
                    {
                        Invoke((MethodInvoker)delegate
                        {
                            MetroMessageBox.Show(this, $"Error resolving MAC address: {ex.Message}",
                                "Warning", MessageBoxButtons.OK, MessageBoxIcon.Warning);

                            // Use default MAC address
                            tbGatewayMac.Text = "FF:FF:FF:FF:FF:FF";
                            HideStatus();
                            cbInterfaces.Enabled = true;
                        });
                    }
                });
            }
            catch (Exception ex)
            {
                MetroMessageBox.Show(this, $"Error updating interface addresses: {ex.Message}",
                    "Interface Error", MessageBoxButtons.OK, MessageBoxIcon.Error, 120);
            }
        }


        private void BtnOk_Click(object sender, EventArgs e)
        {
            var netInfo = ParseNetworkInformation();
            if (netInfo != null)
            {
                Hide();

                var frmMain = new FrmMain(netInfo);
                frmMain.FormClosed += new FormClosedEventHandler((s, args) => Close());
                frmMain.Show(this);
            }
        }

        #endregion
    }
}
