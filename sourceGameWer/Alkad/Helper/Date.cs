using System;

namespace GameWer.Helper
{
  public class Date
  {
    internal static DateTime UnixTimeStampToDateTime(double unixTimeStamp)
    {
      return new DateTime(1970, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc).AddSeconds(unixTimeStamp).ToLocalTime();
    }
  }
}
