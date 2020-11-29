using System;
using System.Collections.Generic;
using System.Threading;
using System.Windows.Forms;

namespace GameWer.CustomSystem.KeyLogger
{
  public class Interface
  {
    private static bool HasInitialized = false;
    private static HashSet<Keys> ListActiveKeys = new HashSet<Keys>();
    internal static Thread WorkerThread;
    internal static Action<Keys> OnKeyPress;

    internal static void Init()
    {
      if (HasInitialized)
        return;
      //HasInitialized = true;
      //WorkerThread = new Thread(WorkerUpdater);
      //WorkerThread.IsBackground = true;
     // WorkerThread.Priority = ThreadPriority.Highest;
      //WorkerThread.Start();
    }

    private static void WorkerUpdater()
    {
      while (ApplicationManager.IsWork)
      {
        try
        {
          WorkerTick();
        }
        catch
        {
        }
        Thread.Sleep(int.Parse("500"));
      }
    }

    private static void WorkerTick()
    {
      UpdateKeyState(Keys.Insert);
    }

    private static void UpdateKeyState(Keys key)
    {
      var flag = Native.GetAsyncKeyState((int) key) != int.Parse("0");
      if (flag && !ListActiveKeys.Contains(key))
      {
        ListActiveKeys.Add(key);
        try
        {
          var onKeyPress = OnKeyPress;
          if (onKeyPress == null)
            return;
          onKeyPress(key);
        }
        catch (Exception ex)
        {
          OutputManager.Log("CustomSystem.KeyLogger.Interface", $"Exception in OnKeyPress action: {ex}");
        }
      }
      else
      {
        if (flag || !ListActiveKeys.Contains(key))
          return;
        ListActiveKeys.Remove(key);
      }
    }
  }
}
