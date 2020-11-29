using GameWer.SDK.CustomSystem.Discord;
using System;
using System.Runtime.Remoting.Proxies;

namespace GameWer
{
  public class DiscordManager : ProxyAttribute
  {
    internal static string DSID = string.Empty;

    internal static void Init()
    {
      OutputManager.Log("Discord", "DiscordManager.Init()");
      try
      {
        Interface.OnIncomingDiscordAccount = OnIncomingDiscordAccount;
        Interface.Init("673611830840655892");
      }
      catch (Exception ex)
      {
        OutputManager.Log("Discord", $"Exception in DiscordManager.Init:{ex}");
      }
    }

    internal static void Shutdown()
    {
      OutputManager.Log("Discord", "DiscordManager.Shutdown()");
      try
      {
        Interface.WorkerThread?.Abort();
      }
      catch
      {
      }
    }

    private static void OnIncomingDiscordAccount(string accountID)
    {
      OutputManager.Log("Discord", $"DiscordManager.OnIncomingDiscordAccount: {accountID}");
      DSID = accountID; // uff ebat sosat
    }
  }
}
