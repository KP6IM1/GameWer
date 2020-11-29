using System;
using System.Threading;

namespace GameWer.Helper
{
  public class Timer
  {
    private bool HasInterval = false;
    private bool HasStop = false;
    private Action CurrentAction;
    private Action<Exception> OnException;
    private TimeSpan Time;

    private Timer()
    {
    }

    private void Start()
    {
      ThreadPool.QueueUserWorkItem(_ =>
      {
        while (!HasStop)
        {
          Thread.Sleep(Time);
          ApplicationManager.SetTaskInMainThread(() =>
          {
            try
            {
              var currentAction = CurrentAction;
              if (currentAction == null)
                return;
              currentAction();
            }
            catch (Exception ex)
            {
              var onException = OnException;
              if (onException == null)
                return;
              onException(ex);
            }
          });
          if (!HasInterval)
            break;
        }
      });
    }

    internal void Stop()
    {
      HasStop = true;
    }

    internal static Timer Timeout(Action action, Action<Exception> exception, float timeout)
    {
      var timer = new Timer();
      timer.CurrentAction = action;
      timer.OnException = exception;
      timer.Time = TimeSpan.FromMilliseconds(timeout * (double) int.Parse("1000"));
      timer.Start();
      return timer;
    }

    internal static Timer Interval(Action action, Action<Exception> exception, float timeout)
    {
      var timer = new Timer();
      timer.CurrentAction = action;
      timer.Time = TimeSpan.FromMilliseconds(timeout * (double) int.Parse("1000"));
      timer.OnException = exception;
      timer.HasInterval = true;
      timer.Start();
      return timer;
    }
  }
}
