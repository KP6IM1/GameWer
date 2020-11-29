using GameWer.Data;
using System;
using System.IO;
using System.Threading;

namespace GameWer
{
  internal static class Bootstrap
  {
    private static Mutex MutexInstance;
    
    [STAThread]
    private static void Main(string[] args)
    {
      try
      {
        DoInit();
      }
      catch (Exception ex)
      {
        File.AppendAllText("./output.log", $"\n[{DateTime.Now}] [Main]: Exception: {ex}");
      }
    }

    private static void DoInit()
    {
      OutputManager.Log(nameof (Bootstrap), "Incoming Main : 4.0.15.0");
      MutexInstance = new Mutex(true, "GameWer");
      if (MutexInstance.WaitOne(TimeSpan.Zero, true) || AppInfo.TargetConnectIP == "127.0.0.1")
      {
        ApplicationManager.Init();
        UIManager.Init();
        ProcessManager.Init();
        KeyManager.Init();
        DiscordManager.Init();
        NetworkManager.Init();
        ApplicationManager.Start();
        ApplicationManager.StartApplicationWorker();
        MutexInstance.ReleaseMutex();
        OutputManager.Log(nameof (Bootstrap), "End of the main thread...");
      }
      else
        OutputManager.Log(nameof (Bootstrap), "Detected duplicate application!");
    }
  }
}
