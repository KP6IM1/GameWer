using GameWer.CustomSystem.KeyLogger;
using System;
using System.Windows.Forms;

namespace GameWer
{
  public class KeyManager
  {
    internal static void Init()
    {
      OutputManager.Log("Key", "KeyManager.Init");
      Interface.OnKeyPress = OnKeyState;
      Interface.Init();
    }

    internal static void Shutdown()
    {
      OutputManager.Log("Key", "KeyManager.Shutdown");
      try
      {
        Interface.WorkerThread?.Abort();
      }
      catch
      {
      }
    }

    private static void OnKeyState(Keys key)
    {
      ApplicationManager.SetTaskInMainThread(() => {});
    }
  }
}
