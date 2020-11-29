using System.Security.Cryptography;
using System.Text;

namespace GameWer.Helper
{
  public class Crypto
  {
    public static string GetMD5FromLine(string input)
    {
      using (var md5 = MD5.Create())
      {
        var bytes = Encoding.ASCII.GetBytes(input);
        var hash = md5.ComputeHash(bytes);
        var stringBuilder = new StringBuilder();
        foreach (var t in hash)
          stringBuilder.Append(t.ToString("X2"));

        return stringBuilder.ToString().ToLower();
      }
    }
  }
}
