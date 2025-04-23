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
        static void Main(string[] args)
        {
            try
            {
                Common.Config.Read();

                // Check if Npcap is installed
                if (PcapDotNet.Core.LivePacketDevice.AllLocalMachine == null ||
                    PcapDotNet.Core.LivePacketDevice.AllLocalMachine.Count == 0)
                {
                    Console.WriteLine("Error: No packet capture devices found. Please ensure Npcap is installed correctly.");
                    return;
                }

                // Check if API mode is requested
                bool apiMode = args.Length > 0 && (args[0] == "--api" || args[0] == "-a");

                if (apiMode)
                {
                    // Start the HTTP server
                    Console.WriteLine("Starting EvilLimiter in API mode...");
                    var server = new HttpServer();
                    server.Start();

                    Console.WriteLine("Press any key to exit...");
                    Console.ReadKey();

                    server.Stop();
                }
                else
                {
                    // Start the GUI
                    Application.EnableVisualStyles();
                    Application.SetCompatibleTextRenderingDefault(false);
                    Application.Run(new Forms.FrmInterface());
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error starting application: {ex.Message}");
                if (args.Length > 0 && (args[0] == "--api" || args[0] == "-a"))
                {
                    Console.WriteLine(ex.StackTrace);
                }
                else
                {
                    MessageBox.Show($"Error starting application: {ex.Message}",
                        "Application Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                }
            }
        }
    }
}