using System;
using System.Runtime.InteropServices;
using System.Text;

namespace GameWer.CustomSystem.Process32
{
  internal class Native
  {
    public static uint TH32CS_SNAPHEAPLIST = 1;
    public static uint TH32CS_SNAPPROCESS = 2;
    public static uint TH32CS_SNAPTHREAD = 4;
    public static uint TH32CS_SNAPMODULE = 8;
    public static uint TH32CS_SNAPMODULE32 = 16;
    public static uint TH32CS_SNAPALL = 15;
    public static uint TH32CS_INHERIT = 2147483648;
    public static uint PROCESS_ALL_ACCESS = 2035711;
    public static uint PROCESS_TERMINATE = 1;
    public static uint PROCESS_CREATE_THREAD = 2;
    public static uint PROCESS_VM_OPERATION = 8;
    public static uint PROCESS_VM_READ = 16;
    public static uint PROCESS_VM_WRITE = 32;
    public static uint PROCESS_DUP_HANDLE = 64;
    public static uint PROCESS_CREATE_PROCESS = 128;
    public static uint PROCESS_SET_QUOTA = 256;
    public static uint PROCESS_SET_INFORMATION = 512;
    public static uint PROCESS_QUERY_INFORMATION = 1024;
    public static uint PROCESS_SUSPEND_RESUME = 2048;
    public static uint PROCESS_QUERY_LIMITED_INFORMATION = 4096;
    public static uint SYNCHRONIZE = 1048576;
    public static readonly IntPtr INVALID_HANDLE_VALUE = new IntPtr(-1);
    private const string KERNEL32 = "kernel32.dll";
    private const string PSAPI = "psapi.dll";

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr CreateToolhelp32Snapshot(uint dwFlags, uint th32ProcessID);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool Process32First(IntPtr hSnapshot, ref ProcessEntry32 lppe);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool Process32Next(IntPtr hSnapshot, ref ProcessEntry32 lppe);

    [DllImport("kernel32.dll")]
    public static extern int CloseHandle(IntPtr handle);

    [DllImport("psapi.dll")]
    public static extern uint GetProcessImageFileName(
      IntPtr hProcess,
      [Out] StringBuilder lpImageFileName,
      [MarshalAs(UnmanagedType.U4), In] int nSize);

    [DllImport("psapi.dll", CharSet = CharSet.Auto, SetLastError = true)]
    public static extern uint GetModuleFileNameEx(
      IntPtr hProcess,
      IntPtr hModule,
      [Out] StringBuilder lpBaseName,
      [MarshalAs(UnmanagedType.U4), In] int nSize);

    [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
    public static extern int GetClassName(IntPtr hWnd, StringBuilder lpClassName, int nMaxCount);

    [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
    private static extern bool QueryFullProcessImageName(
      IntPtr hProcess,
      uint dwFlags,
      [MarshalAs(UnmanagedType.LPTStr), Out] StringBuilder lpExeName,
      ref uint lpdwSize);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr OpenProcess(
      uint dwDesiredAccess,
      int bInheritHandle,
      uint dwProcessId);

    public struct ProcessEntry32
    {
      public uint dwSize;
      public uint cntUsage;
      public uint th32ProcessID;
      public IntPtr th32DefaultHeapID;
      public uint th32ModuleID;
      public uint cntThreads;
      public uint th32ParentProcessID;
      public int pcPriClassBase;
      public uint dwFlags;
      [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
      public string szExeFile;
    }
  }
}
