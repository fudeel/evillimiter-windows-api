// EvilLimiter.Windows/Program.cs
using EvilLimiter.Windows.Common;
using EvilLimiter.Windows.Forms;
using EvilLimiter.Windows.API;
using PcapDotNet.Core;
using System;
using System.Windows.Forms;
using System.Linq;

namespace EvilLimiter.Windows
{
    static class Program
    {
        [STAThread]
        static void Main(string[] args)
        {
            try
            {
                Config.Read();

                // Check for Npcap installation
                if (LivePacketDevice.AllLocalMachine == null || LivePacketDevice.AllLocalMachine.Count == 0)
                {
                    if (args.Length > 0 && args[0] == "--api")
                    {
                        Console.WriteLine("No packet capture devices found. Please ensure Npcap is installed correctly.");
                        return;
                    }
                    else
                    {
                        MessageBox.Show("No packet capture devices found. Please ensure Npcap is installed correctly.",
                            "Missing Dependency", MessageBoxButtons.OK, MessageBoxIcon.Error);
                        return;
                    }
                }

                // Check for API mode
                if (args.Length > 0 && args[0] == "--api")
                {
                    RunApiMode();
                }
                else
                {
                    // Run in GUI mode
                    Application.EnableVisualStyles();
                    Application.SetCompatibleTextRenderingDefault(false);
                    Application.Run(new FrmInterface());
                }
            }
            catch (Exception ex)
            {
                if (args.Length > 0 && args[0] == "--api")
                {
                    Console.WriteLine($"Error starting application: {ex.Message}\n\nStack Trace: {ex.StackTrace}");
                }
                else
                {
                    MessageBox.Show($"Error starting application: {ex.Message}\n\nStack Trace: {ex.StackTrace}",
                        "Application Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                }
            }
        }

        private static void RunApiMode()
        {
            Console.WriteLine("Starting EvilLimiter in API mode...");
            var apiServer = new ApiServer();
            apiServer.StartServer();
        }
    }
}