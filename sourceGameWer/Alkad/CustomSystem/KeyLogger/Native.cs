using System.Runtime.InteropServices;

namespace GameWer.CustomSystem.KeyLogger
{
  public class Native
  {
    [DllImport("user32.dll")]
    public static extern int GetAsyncKeyState(int i);
  }
}
