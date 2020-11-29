namespace GameWer
{
  internal class DeProtectType
  {
    private static int lastResult = 0;

    public static int GetPacketKey(bool clear)
    {
      var result = 0;
      int i;
      
      if (clear)
      {
        lastResult = 0;
      }  
      else
      {
        for (i = lastResult++ + 1; (i & 1) == 0 || i == 5 * (i / 5) || i == 7 * (i / 7) || i == 9 * (i / 9); ++i);
        result = i;
        lastResult = i;
      }

      return result;
    }
  }
}
