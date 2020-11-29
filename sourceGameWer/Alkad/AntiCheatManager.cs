using GameWer.Helper;
using GameWer.Struct;
using System;
using System.Collections.Generic;
using WebSocketSharp;

namespace GameWer
{
  public class AntiCheatManager
  {
    private static string LastKeySession = string.Empty;
    private static string LastPublicKey = string.Empty;
    private static string LastPrivateKey = string.Empty;

    private static BannedPlayerResultPacket CurrentBannedPlayerResultPacket { get; set; } = (BannedPlayerResultPacket) null;

    private static void OnNetworkAuthResultPacketInternal(NetworkAuthResultPacket packet)
    {
      LastKeySession = packet.SessionKey;
      LastPrivateKey = packet.PrivateKey;
      if (CurrentBannedPlayerResultPacket != null)
        OnNetworkBannedPlayerPacket(CurrentBannedPlayerResultPacket);
      NetworkManager.Send(new NetworkDetailsPlayerPacket()
      {
        Hwid_list = string.Join(",", CustomSystem.Information.Interface.GetHWIDList),
        Modle = CustomSystem.Information.Interface.Model,
        Driversname = CustomSystem.Information.Interface.DriversName,
        Driverssize = int.Parse(CustomSystem.Information.Interface.DriversSize),
        Machinename = CustomSystem.Information.Interface.MachineName,
        Manufacturer = CustomSystem.Information.Interface.Manufacturer,
        Memorysize = int.Parse(CustomSystem.Information.Interface.MemorySize),
        Organization = CustomSystem.Information.Interface.RegisteredOrganization,
        Owner = CustomSystem.Information.Interface.RegisteredOwner,
        Processorid = CustomSystem.Information.Interface.ProcessorID,
        Processorname = CustomSystem.Information.Interface.ProcessorName,
        Productname = CustomSystem.Information.Interface.ProductName,
        Systemroot = CustomSystem.Information.Interface.SystemRoot,
        Username = CustomSystem.Information.Interface.UserName,
        Videoid = CustomSystem.Information.Interface.VideocardID,
        Videoname = CustomSystem.Information.Interface.VideocardName,
        IsBit64 = CustomSystem.Information.Interface.IsBit64OS,
        PrivateKeyHash = Crypto.GetMD5FromLine($"{LastPublicKey}{LastPrivateKey}.1")
      }.ParseJSON());
    }

    private static void OnNetworkAuthResultPacket(NetworkAuthResultPacket packet)
    {
      try
      {
        OutputManager.Log("AntiCheat", $"AntiCheatManager.OnNetworkAuthResultPacket: {packet.Result}");
        UIManager.ProxyForm.OnNetworkAuthSuccess();
        OnNetworkAuthResultPacketInternal(packet);
      }
      catch (Exception ex)
      {
        OutputManager.Log("AntiCheat", $"Exception in AntiCheatManager.OnNetworkAuthResultPacket: {ex}");
      }
    }

    private static void OnNetworkBadVersionPacket(NetworkBadVersionPacket packet)
    {
      try
      {
        OutputManager.Log("AntiCheat", "AntiCheatManager.OnNetworkBadVersionPacket");
        UIManager.ProxyForm.OnApplicationState("badVersion");
        NetworkManager.NotNeedReconnect = true;
      }
      catch (Exception ex)
      {
        OutputManager.Log("AntiCheat", $"Exception in AntiCheatManager.OnNetworkBadVersionPacket: {ex}");
      }
    }

    private static void OnNetworkProcessesSystemReady(
      NetworkProcessesSystemReady networkProcessesSystemReady)
    {
      try
      {
        OutputManager.Log("AntiCheat", "AntiCheatManager.OnNetworkProcessesSystemReady");
        ProcessManager.ListSendPath = new HashSet<string>();
        ProcessManager.DoSendNewProcesses();
      }
      catch (Exception ex)
      {
        OutputManager.Log("AntiCheat", $"Exception in AntiCheatManager.OnNetworkProcessesSystemReady: {ex}");
      }
    }

    internal static void OnNetworkPacket(
      string method,
      string fullContent,
      Dictionary<string, object> packet)
    {
      try
      {
        switch (method)
        {
          case "authResult":
            var packet1 = NetworkAuthResultPacket.ParseObject(packet);
            if (packet1.Result)
            {
              OnNetworkAuthResultPacket(packet1);
              break;
            }
            NetworkManager.BaseSocket.CloseAsync(CloseStatusCode.UnsupportedData);
            break;
          case "badVersion":
            OnNetworkBadVersionPacket(new NetworkBadVersionPacket());
            break;
          case "processesReady":
            OnNetworkProcessesSystemReady(new NetworkProcessesSystemReady());
            break;
          case "bannedResult":
            OnNetworkBannedPlayerPacket(BannedPlayerResultPacket.ParseObject(packet));
            break;
        }
      }
      catch (Exception ex)
      {
        OutputManager.Log("AntiCheat", $"Exception in AntiCheatManager.OnNetworkPacket: {ex}");
      }
    }

    private static void OnNetworkBannedPlayerPacket(
      BannedPlayerResultPacket bannedPlayerResultPacket)
    {
      try
      {
        OutputManager.Log("AntiCheat",
          $"AntiCheatManager.OnNetworkBannedResultPacket: {bannedPlayerResultPacket.Reason}, {Date.UnixTimeStampToDateTime(bannedPlayerResultPacket.FinishAt)}");
        var dateTime = Date.UnixTimeStampToDateTime(bannedPlayerResultPacket.FinishAt);
        CurrentBannedPlayerResultPacket = bannedPlayerResultPacket;
        UIManager.ProxyForm.OnIncomingBanned(bannedPlayerResultPacket.Reason, dateTime);
      }
      catch (Exception ex)
      {
        OutputManager.Log("AntiCheat", $"Exception in AntiCheatManager.OnNetworkBannedResultPacket: {ex}");
      }
    }

    internal static void OnNetworkDisconnected(string reason)
    {
      try
      {
        OutputManager.Log("AntiCheat", $"AntiCheatManager.OnNetworkDisconnected({reason})");
        ProcessManager.ListSendPath = null;
        CurrentBannedPlayerResultPacket = null;
        UIManager.ProxyForm.OnNetworkDisconnected(reason);
        if (!ApplicationManager.IsWork)
          return;
        Timer.Timeout(() =>
        {
          if (NetworkManager.NotNeedReconnect == (int.Parse("0") == 1))
            NetworkManager.BaseSocket.ConnectAsync();
          else
            OutputManager.Log("AntiCheat", "AntiCheatManager.OnNetworkDisconnected::DetectedNoReconnect");
        }, ex => OutputManager.Log("Network", $"NetworkManager.OnNetworkClose::ReconnectingException:{ex}"), 3f);
      }
      catch (Exception ex)
      {
        OutputManager.Log("AntiCheat", $"Exception in AntiCheatManager.OnNetworkDisconnected: {ex}");
      }
    }

    private static void OnNetworkConnectedInternal()
    {
      LastPublicKey = Crypto.GetMD5FromLine(DateTime.Now.ToString());
      NetworkManager.Send(new NetworkAuthPacket()
      {
        Version = "4.0.15.0",
        SteamID = CustomSystem.Steamwork.Interface.GetSteamID().ToString().Substring(0, 17),
        HWID = CustomSystem.Information.Interface.GetHWID,
        PCID = CustomSystem.Information.Interface.PCID,
        DSID = DiscordManager.DSID,
        LastSessionKey = LastKeySession,
        PublicKey = LastPublicKey,
        PublicKeyHash = Crypto.GetMD5FromLine($"{LastPublicKey}.1")
      }.ParseJSON());
    }

    internal static void OnNetworkConnected()
    {
      try
      {
        OutputManager.Log("AntiCheat", "AntiCheatManager.OnNetworkConnected()");
        UIManager.ProxyForm.OnNetworkConnected();
        OnNetworkConnectedInternal();
      }
      catch (Exception ex)
      {
        OutputManager.Log("AntiCheat", $"Exception in AntiCheatManager.OnNetworkConnected: {ex}");
      }
    }
  }
}
