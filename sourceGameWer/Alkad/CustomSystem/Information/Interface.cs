using GameWer.Helper;
using Microsoft.VisualBasic.Devices;
using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Management;
using System.Net.NetworkInformation;
using System.Windows.Forms;

namespace GameWer.CustomSystem.Information
{
  public class Interface
  {
    internal static string GetHWID = string.Empty;
    internal static string PCID = string.Empty;
    internal static string Model = string.Empty;
    internal static string Manufacturer = string.Empty;
    internal static string ProductName = string.Empty;
    internal static string RegisteredOrganization = string.Empty;
    internal static string RegisteredOwner = string.Empty;
    internal static string SystemRoot = string.Empty;
    internal static string MachineName = string.Empty;
    internal static string UserName = string.Empty;
    internal static bool IsBit64OS = false;
    internal static string MemorySize = string.Empty;
    internal static string ProcessorName = string.Empty;
    internal static string ProcessorID = string.Empty;
    internal static string VideocardName = string.Empty;
    internal static string VideocardID = string.Empty;
    internal static string DriversName = string.Empty;
    internal static string DriversSize = string.Empty;

    internal static List<string> GetHWIDList { get; } = new List<string>();

    internal static void Init()
    {
      InitHWIDList();
      InitHWID();
      InitOther();
    }

    private static void InitOther()
    {
      DriversName = string.Join(",", Environment.GetLogicalDrives());
      try
      {
        var num = uint.Parse("0");
        foreach (var drive in DriveInfo.GetDrives())
        {
          try
          {
            num += (uint) ((ulong) drive.TotalSize / (ulong) int.Parse("1024") / (ulong) int.Parse("1024"));
          }
          catch
          {
          }
        }
        DriversSize = num.ToString();
      }
      catch (Exception)
      {
      }
      try
      {
        foreach (var instance in new ManagementClass("Win32_Processor").GetInstances())
        {
          foreach (var property in instance.Properties)
          {
            switch (property.Name)
            {
              case "Name":
                ProcessorName = property.Value.ToString();
                break;
              case "ProcessorId":
              case "ProcessorType":
              case "ProcessorRevision":
                ProcessorID += property.Value.ToString();
                break;
            }
          }
        }
      }
      catch (Exception)
      {
      }
      try
      {
        foreach (var instance in new ManagementClass("Win32_VideoController").GetInstances())
        {
          try
          {
            foreach (var property in instance.Properties)
            {
              try
              {
                switch (property.Name)
                {
                  case "Name":
                    VideocardName = property.Value.ToString();
                    break;
                  case "PNPDeviceID":
                    VideocardID = property.Value.ToString();
                    break;
                }
              }
              catch
              {
              }
            }
          }
          catch
          {
          }
        }
      }
      catch (Exception)
      {
        Console.WriteLine("GetGPU Crash");
      }
      try
      {
        Model = Registry.GetValue("HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\OEMInformation\\", "Model", "null").ToString();
      }
      catch
      {
      }
      try
      {
        Manufacturer = Registry.GetValue("HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\OEMInformation\\", "Manufacturer", "null").ToString();
      }
      catch
      {
      }
      try
      {
        ProductName = Registry.GetValue("HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", "ProductName", "null").ToString();
      }
      catch
      {
      }
      try
      {
        RegisteredOrganization = Registry.GetValue("HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", "RegisteredOrganization", "null").ToString();
      }
      catch
      {
      }
      try
      {
        RegisteredOwner = Registry.GetValue("HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", "RegisteredOwner", "null").ToString();
      }
      catch
      {
      }
      try
      {
        SystemRoot = Registry.GetValue("HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", "SystemRoot", "null").ToString();
      }
      catch
      {
      }
      try
      {
        MachineName = Environment.MachineName;
      }
      catch
      {
      }
      try
      {
        UserName = Environment.UserName;
      }
      catch
      {
      }
      try
      {
        IsBit64OS = Environment.Is64BitOperatingSystem;
      }
      catch
      {
      }
      try
      {
        MemorySize = ((int) (new ComputerInfo().TotalPhysicalMemory / ulong.Parse("1024") / ulong.Parse("1024"))).ToString();
      }
      catch
      {
      }
      try
      {
                PCID = Crypto.GetMD5FromLine(MemorySize + DriversSize + DriversName + VideocardName + ProcessorName);
            }
      catch
      {
      }
    }

    private static void InitHWID()
    {
            if (GetHWIDList.Count <= int.Parse("0"))
        return;
      GetHWID = Crypto.GetMD5FromLine(GetHWIDList[int.Parse("0")] + (GetHWIDList.Count > int.Parse("1") ? GetHWIDList[int.Parse("1")] : ""));
    }

    private static void InitHWIDList()
    {
      var strArray1 = new string[3]
      {
        "ff-ff-ff-ff-ff-ff",
        "7a-79-19-00-00-01",
        "02-00-00-00-51-00"
      };
      try
      {
        var streamReader = ExecuteCommandLine("arp", "-a");
        for (var index = 0; index < int.Parse("3"); ++index)
          streamReader.ReadLine();
        while (!streamReader.EndOfStream)
        {
          var str1 = streamReader.ReadLine();
          if (str1 != null)
          {
            var str2 = str1.Trim();
            while (str2.Contains("  "))
              str2 = str2.Replace("  ", " ");
            var strArray2 = str2.Trim().Split(' ');
            if (strArray2.Length == int.Parse("3"))
            {
              var str3 = strArray2[int.Parse("0")];
              var input = strArray2[int.Parse("1")];
              if (!strArray1.Contains<string>(input))
              {
                var strArray3 = str3.Split(new char[1]
                {
                  '.'
                }, StringSplitOptions.RemoveEmptyEntries);
                if (strArray3.Length != int.Parse("4") || (!(strArray3[1] == "255") || !(strArray3[2] == "255")) && (!(strArray3[1] == "0") || !(strArray3[2] == "0")))
                  GetHWIDList.Add(Crypto.GetMD5FromLine(input));
              }
            }
          }
        }
      }
      catch
      {
      }
      var input1 = NetworkInterface.GetAllNetworkInterfaces().Where<NetworkInterface>(nic => nic.OperationalStatus == OperationalStatus.Up && nic.NetworkInterfaceType != NetworkInterfaceType.Loopback).Select<NetworkInterface, string>(nic => nic.GetPhysicalAddress().ToString()).FirstOrDefault<string>();
      if (strArray1.Contains<string>(input1))
        return;
      GetHWIDList.Add(Crypto.GetMD5FromLine(input1));
    }

    private static StreamReader ExecuteCommandLine(string file, string arguments = "")
    {
      return Process.Start(new ProcessStartInfo()
      {
        CreateNoWindow = true,
        WindowStyle = ProcessWindowStyle.Hidden,
        UseShellExecute = false,
        RedirectStandardOutput = true,
        FileName = file,
        Arguments = arguments
      })?.StandardOutput;
    }
  }
}
