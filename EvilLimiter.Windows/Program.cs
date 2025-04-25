using EvilLimiter.Windows.Common;
using EvilLimiter.Windows.Forms;
using PcapDotNet.Core;
using System;
using System.Windows.Forms;

namespace EvilLimiter.Windows
{
    static class Program
    {
        [STAThread]
        static void Main()
        {
            try
            {
                Config.Read();
                Application.EnableVisualStyles();
                Application.SetCompatibleTextRenderingDefault(false);

                // Check for Npcap installation
                if (LivePacketDevice.AllLocalMachine == null || LivePacketDevice.AllLocalMachine.Count == 0)
                {
                    MessageBox.Show("No packet capture devices found. Please ensure Npcap is installed correctly.",
                        "Missing Dependency", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    return;
                }

                Application.Run(new FrmInterface());
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error starting application: {ex.Message}\n\nStack Trace: {ex.StackTrace}",
                    "Application Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }
    }
}
