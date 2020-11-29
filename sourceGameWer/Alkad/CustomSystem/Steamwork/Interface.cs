using GameWer.CustomSystem.Process32;
using GameWer.Helper;
using Microsoft.Win32;
using System;
using System.Diagnostics;
using System.IO;
using Steamworks;

namespace GameWer.CustomSystem.Steamwork
{
  public class Interface
  {
    private static string SteamPath = null;
    private static string LastSteamIDHash = "";
    private static ulong LastSteamID = 0;

    internal static string GetSteamPath()
    {
      if (string.IsNullOrEmpty(SteamPath))
      {
        SteamPath = GetUserValue();
        if (string.IsNullOrEmpty(SteamPath))
        {
          SteamPath = GetFullValue();
          if (string.IsNullOrEmpty(SteamPath))
          {
            SteamPath = GetProcessValue();
            if (string.IsNullOrEmpty(SteamPath))
              SteamPath = GetFinishValue();
          }
        }
      }
      return SteamPath;
    }

    internal static bool HasSteamRunned()
    {
      try
      {
        return Process.GetProcessesByName("Steam").Length != int.Parse("0");
      }
      catch (Exception ex)
      {
        OutputManager.Log("CustomSystem.Steamwork.Interface", $"Exception in HasSteamRunned: {ex}");
      }
      return false;
    }

    internal static ulong GetSteamID()
    {
      if (LastSteamID == 0UL)
      {
        try
        {
          SteamClient.Init(uint.Parse("480"), true);
          LastSteamID = SteamClient.SteamId;
          LastSteamIDHash = Crypto.GetMD5FromLine($"{LastSteamID}...");
          SteamClient.Shutdown();
        }
        catch
        {
          try
          {
            SteamClient.Shutdown();
          }
          catch
          {
          }
        }
      }
      else if (Crypto.GetMD5FromLine($"{LastSteamID}...") != LastSteamIDHash)
      {
        Environment.Exit(0);
        return 0;
      }
      return LastSteamID;
    }

    private static string GetProcessValue()
    {
      try
      {
        var processesByName = Process.GetProcessesByName("Steam");
        if ((uint) processesByName.Length > 0U)
          return new FileInfo(processesByName[int.Parse("0")].MainModule.FileName).DirectoryName;
      }
      catch
      {
      }
      return string.Empty;
    }

    private static string GetFinishValue()
    {
      try
      {
        var processesList = GameWer.CustomSystem.Process32.Interface.GetProcessesList();
        for (var index = 0; index < processesList.Length; ++index)
        {
          if (processesList[index].Name.ToLower() == "steam" && !string.IsNullOrEmpty(processesList[index].DirectoryPath))
            return processesList[index].DirectoryPath;
        }
      }
      catch
      {
      }
      return string.Empty;
    }

    private static string GetFullValue()
    {
      var path = "";
      try
      {
        var registryKey = Registry.LocalMachine.OpenSubKey("software\\valve\\steam");
        path = (string) registryKey.GetValue("SteamPath");
        registryKey.Close();
      }
      catch
      {
      }
      if (string.IsNullOrEmpty(path) == (int.Parse("1") == 0))
        path = new DirectoryInfo(path).FullName;
      return path;
    }

    private static string GetUserValue()
    {
      var path = "";
      try
      {
        var registryKey = Registry.CurrentUser.OpenSubKey("software\\valve\\steam");
        path = (string) registryKey.GetValue("SteamPath");
        registryKey.Close();
      }
      catch
      {
      }
      if (string.IsNullOrEmpty(path) == (int.Parse("1") == 0))
        path = new DirectoryInfo(path).FullName;
      return path;
    }
  }
}
