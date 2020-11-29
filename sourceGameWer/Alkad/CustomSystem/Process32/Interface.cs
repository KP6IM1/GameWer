using GameWer.Helper;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;

namespace GameWer.CustomSystem.Process32
{
  public class Interface
  {
    private static bool HasInitialized = false;
    private static readonly HashSet<uint> ListViewPID = new HashSet<uint>();
    private static readonly Dictionary<string, EntryItem> InfoPath = new Dictionary<string, EntryItem>();
    private static readonly List<EntryItem> ListProcesses = new List<EntryItem>();
    private static readonly uint DWSize = (uint) Marshal.SizeOf(typeof (Native.ProcessEntry32));
    internal static Thread WorkerThread;
    public static Action<EntryItem> OnProcess;

    public static void Init()
    {
      if (HasInitialized)
        return;
      HasInitialized = true;
      WorkerThread = new Thread(WorkerUpdater);
      WorkerThread.IsBackground = true;
      WorkerThread.Priority = ThreadPriority.Highest;
      WorkerThread.Start();
    }

    public static EntryItem[] GetProcessesList()
    {
      EntryItem[] array;
      lock (ListProcesses)
      {
        array = new EntryItem[ListProcesses.Count];
        ListProcesses.CopyTo(array);
      }
      return array;
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
        Thread.Sleep(int.Parse("300"));
      }
    }

    private static void WorkerTick()
    {
      var lppe = new Native.ProcessEntry32();
      var toolhelp32Snapshot = Native.CreateToolhelp32Snapshot(Native.TH32CS_SNAPPROCESS, uint.Parse("0"));
      if (toolhelp32Snapshot == Native.INVALID_HANDLE_VALUE)
        return;
      lppe.dwSize = DWSize;
      if (!Native.Process32First(toolhelp32Snapshot, ref lppe))
        return;
      do
      {
        if (!ListViewPID.Contains(lppe.th32ProcessID))
        {
          ListViewPID.Add(lppe.th32ProcessID);
          IncomingProcess(lppe);
        }
      }
      while (Native.Process32Next(toolhelp32Snapshot, ref lppe) && ApplicationManager.IsWork);
      Native.CloseHandle(toolhelp32Snapshot);
    }

    private static void FinishProcess(EntryItem process)
    {
      var length = process.Name.IndexOf('.');
      if (length != int.Parse("-1"))
        process.Name = process.Name.Substring(int.Parse("0"), length);
      lock (ListProcesses)
        ListProcesses.Add(process);
      try
      {
        var onProcess = OnProcess;
        if (onProcess == null)
          return;
        onProcess(process);
      }
      catch (Exception ex)
      {
        OutputManager.Log("CustomSystem.Process32.Interface", $"Exception in FinishProcess action: {ex}");
      }
    }

    private static bool HasSecureFile(string path)
    {
      try
      {
        var x509Certificate2 = new X509Certificate2(X509Certificate.CreateFromSignedFile(path));
        return true;
      }
      catch
      {
      }
      return false;
    }

    private static void DetailsScan(EntryItem entry)
    {
      ThreadPool.QueueUserWorkItem(_ =>
      {
        try
        {
          if (File.Exists(entry.FilePath))
          {
            entry.Origin = FileVersionInfo.GetVersionInfo(entry.FilePath).OriginalFilename;
            entry.DirectoryPath = new FileInfo(new DirectoryInfo(entry.FilePath).FullName).Directory.FullName;
            if (Directory.Exists($"{entry.DirectoryPath}/{entry.Name}_Data/"))
            {
              var fileInfoList = new List<FileInfo>();
              if (Directory.Exists($"{entry.DirectoryPath}/{entry.Name}_Data/"))
              {
                var files = new DirectoryInfo($"{entry.DirectoryPath}/{entry.Name}_Data/").GetFiles("*.dll");
                fileInfoList.AddRange(files);
              }
              if (Directory.Exists($"{entry.DirectoryPath}/{entry.Name}_Data/"))
              {
                var files = new DirectoryInfo($"{entry.DirectoryPath}/{entry.Name}_Data/").GetFiles("*.dll");
                fileInfoList.AddRange(files);
              }
              for (var index = 0; index < fileInfoList.Count; ++index)
              {
                var fileInfo = fileInfoList[index];
                lock (InfoPath)
                {
                  if (!InfoPath.ContainsKey(fileInfo.FullName))
                  {
                    var entry1 = new EntryItem();
                    entry1.Name = fileInfo.Name.Substring(0, fileInfo.Name.Length - fileInfo.Extension.Length - 1);
                    entry1.FilePath = fileInfo.FullName;
                    entry1.DirectoryPath = fileInfo.Directory.FullName;
                    entry1.ID = 0U;
                    InfoPath.Add(fileInfo.FullName, entry1);
                    DetailsScan(entry1);
                  }
                }
              }
            }
            try
            {
              entry.Length = new FileInfo(entry.FilePath).Length;
            }
            catch
            {
            }
            entry.Secure = HasSecureFile(entry.FilePath);
            using (var md5 = MD5.Create())
            {
              using (var fileStream = File.OpenRead(entry.FilePath))
                entry.Info = BitConverter.ToString(md5.ComputeHash(fileStream)).Replace("-", "").ToLowerInvariant();
            }
          }
          else
          {
            entry.Secure = false;
            entry.Info = Crypto.GetMD5FromLine(entry.Name);
            entry.Length = 0L;
          }
        }
        catch (Exception ex)
        {
          OutputManager.Log("CustomSystem.Process32.Interface", $"Exception in DetailsScan: {ex}");
        }
        FinishProcess(entry);
      });
    }

    private static string GetPathFromNative(Native.ProcessEntry32 pe32)
    {
      var path = "";
      try
      {
        var num1 = Native.OpenProcess(Native.PROCESS_QUERY_INFORMATION, 0, pe32.th32ProcessID);
        if (num1 != IntPtr.Zero && num1 != Native.INVALID_HANDLE_VALUE)
        {
          var num2 = int.Parse("1024");
          try
          {
            try
            {
              var stringBuilder = new StringBuilder(num2);
              var moduleFileNameEx = (int) Native.GetModuleFileNameEx(num1, IntPtr.Zero, stringBuilder, num2);
              if (stringBuilder.Length == int.Parse("0"))
              {
                var processImageFileName = (int) Native.GetProcessImageFileName(num1, stringBuilder, num2);
              }
              path = stringBuilder.ToString();
              if (string.IsNullOrEmpty(path) || !File.Exists(path))
                throw new Exception("FilePath not found");
            }
            catch
            {
              try
              {
                var lpImageFileName = new StringBuilder(num2);
                var processImageFileName = (int) Native.GetProcessImageFileName(num1, lpImageFileName, num2);
                path = lpImageFileName.ToString();
                if (string.IsNullOrEmpty(path) || !File.Exists(path))
                  throw new Exception("FilePath not found");
              }
              catch
              {
              }
            }
          }
          catch (Exception)
          {
          }
          Native.CloseHandle(num1);
        }
      }
      catch
      {
      }
      return path;
    }

    private static void IncomingProcess(Native.ProcessEntry32 pe32)
    {
      if (pe32.th32ProcessID < int.Parse("10"))
        return;
      try
      {
        EntryItem entryItem;
        try
        {
          var processById = Process.GetProcessById((int) pe32.th32ProcessID);
          var fileName = processById.MainModule.FileName;
          entryItem = new EntryItem()
          {
            ID = pe32.th32ProcessID,
            Name = processById.ProcessName.EndsWith(".exe") ? processById.ProcessName.Substring(0, processById.ProcessName.Length - 4) : processById.ProcessName,
            FilePath = fileName
          };
          var lpClassName = new StringBuilder(512);
          Native.GetClassName(processById.MainWindowHandle, lpClassName, 512);
          try
          {
            entryItem.Class = lpClassName.ToString();
            entryItem.Title = processById.MainWindowTitle;
          }
          catch
          {
          }
        }
        catch (Exception)
        {
          var pathFromNative = GetPathFromNative(pe32);
          entryItem = new EntryItem()
          {
            ID = pe32.th32ProcessID,
            Name = pe32.szExeFile.EndsWith(".exe") ? pe32.szExeFile.Substring(0, pe32.szExeFile.Length - 4) : pe32.szExeFile,
            FilePath = pathFromNative
          };
        }
        if (entryItem.Name.EndsWith(".exe"))
          entryItem.Name = entryItem.Name.Substring(0, entryItem.Name.Length - 4);
        if (string.IsNullOrEmpty(entryItem.FilePath) || !File.Exists(entryItem.FilePath))
        {
          entryItem.FilePath = entryItem.Name;
          entryItem.DirectoryPath = "";
          entryItem.Secure = false;
          entryItem.Info = Crypto.GetMD5FromLine(entryItem.Name);
          entryItem.Length = 0L;
          FinishProcess(entryItem);
        }
        else
        {
          var lower = entryItem.FilePath.ToLower();
          if (!lower.Contains("windows") && !lower.Contains("program files"))
            ProcessAnalytics(entryItem);
          lock (InfoPath)
          {
            if (!InfoPath.ContainsKey(entryItem.FilePath))
            {
              InfoPath[entryItem.FilePath] = entryItem;
              DetailsScan(entryItem);
              return;
            }
            long num = 0;
            try
            {
              num = new FileInfo(entryItem.FilePath).Length;
            }
            catch
            {
            }
            if (num == InfoPath[entryItem.FilePath].Length)
            {
              entryItem.Length = num;
              entryItem.Info = InfoPath[entryItem.FilePath].Info;
              entryItem.Secure = InfoPath[entryItem.FilePath].Secure;
            }
            else
            {
              InfoPath[entryItem.FilePath] = entryItem;
              DetailsScan(entryItem);
              return;
            }
          }
          FinishProcess(entryItem);
        }
      }
      catch (Exception ex)
      {
        OutputManager.Log("CustomSystem.Process32.Interface", $"Exception in IncomingProcess: {ex}");
      }
    }

    private static void ProcessAnalytics(EntryItem entry)
    {
      ThreadPool.QueueUserWorkItem(_ =>
      {
        try
        {
          if (new FileInfo(entry.FilePath).Length >= 10485760L)
            return;
          var str = Encoding.UTF8.GetString(File.ReadAllBytes(entry.FilePath));
          if (str.Contains("dnSpy.Contracts.DnSpy"))
          {
            Process.GetProcessById((int) entry.ID)?.Kill();
            ApplicationManager.Shutdown();
          }
          else if (str.Contains("Mega_Dumper"))
          {
            Process.GetProcessById((int) entry.ID)?.Kill();
            ApplicationManager.Shutdown();
          }
          else if (str.Contains("PhShellProcessHacker"))
          {
            Process.GetProcessById((int) entry.ID)?.Kill();
            ApplicationManager.Shutdown();
          }
          else if (str.Contains("x64dbg"))
          {
            Process.GetProcessById((int) entry.ID)?.Kill();
            ApplicationManager.Shutdown();
          }
          else if (str.Contains("IDA Pro"))
          {
            Process.GetProcessById((int) entry.ID)?.Kill();
            ApplicationManager.Shutdown();
          }
          else if (str.Contains("https://wiki.cheatengine.org/index.php"))
          { 
            Process.GetProcessById((int) entry.ID)?.Kill();
            ApplicationManager.Shutdown();
          }
          else
          {
            if (!str.Contains("WINDBG_NO_WORKSPACE_WINDOWS"))
              return;
            Process.GetProcessById((int) entry.ID)?.Kill();
            ApplicationManager.Shutdown();
          }
        }
        catch
        {
          try
          {
            ApplicationManager.Shutdown();
          }
          catch
          {
          }
        }
      });
    }
  }
}
