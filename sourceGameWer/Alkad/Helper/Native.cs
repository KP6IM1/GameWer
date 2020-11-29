using System;
using System.Reflection;
using System.Runtime.InteropServices;

namespace GameWer.Helper
{
  public class Native
  {
    private static IntPtr Instance = IntPtr.Zero;
    private const string CONST_NATIVE_PATH = "GameWer.Native.dll";

    static Native()
    {
      foreach (MemberInfo method in typeof (Native).GetMethods(BindingFlags.Instance | BindingFlags.Static | BindingFlags.NonPublic | BindingFlags.CreateInstance))
      {
        try
        {
          var customAttributes = method.GetCustomAttributes(typeof (DllImportAttribute), true);
          if ((uint) customAttributes.Length > 0U)
          {
            var dllImportAttribute = customAttributes[0] as DllImportAttribute;
            dllImportAttribute.GetType().GetField("_val", BindingFlags.Instance | BindingFlags.Static | BindingFlags.NonPublic | BindingFlags.CreateInstance).SetValue(dllImportAttribute,
              $"{AppDomain.CurrentDomain.BaseDirectory}/GameWer.Native.dll");
          }
        }
        catch (Exception)
        {
        }
      }
    }

    [DllImport("GameWer.Native.dll", CallingConvention = CallingConvention.Cdecl)]
    private static extern IntPtr CreateInstance();

    [DllImport("GameWer.Native.dll", CallingConvention = CallingConvention.Cdecl)]
    private static extern IntPtr StringEncryptionLevelOne(
      IntPtr instance,
      IntPtr line,
      int len);

    [DllImport("GameWer.Native.dll", CallingConvention = CallingConvention.Cdecl)]
    private static extern IntPtr StringEncryptionLevelTwo(
      IntPtr instance,
      IntPtr line,
      int len);

    [DllImport("GameWer.Native.dll", CallingConvention = CallingConvention.Cdecl)]
    private static extern IntPtr StringEncryptionLevelThree(
      IntPtr instance,
      IntPtr line,
      int len);

    [DllImport("GameWer.Native.dll", CallingConvention = CallingConvention.Cdecl)]
    private static extern IntPtr StringEncryptionLevelFour(
      IntPtr instance,
      IntPtr line,
      int len);

    [DllImport("GameWer.Native.dll", CallingConvention = CallingConvention.Cdecl)]
    private static extern void ClearEncryptionLevelFour(IntPtr instance);

    public static string StringEncryptionLevelOne(string line)
    {
      if (Instance == IntPtr.Zero)
        Instance = CreateInstance();
      return StringEncryptionLevelOne(Instance, line.ToPointer(), line.Length).StringFromPointer(line.Length * 2);
    }

    public static string StringEncryptionLevelTwo(string line)
    {
      if (Instance == IntPtr.Zero)
        Instance = CreateInstance();
      return StringEncryptionLevelTwo(Instance, line.ToPointer(), line.Length).StringFromPointer(line.Length * 2);
    }

    public static string StringEncryptionLevelThree(string line)
    {
      if (Instance == IntPtr.Zero)
        Instance = CreateInstance();
      return StringEncryptionLevelThree(Instance, line.ToPointer(), line.Length).StringFromPointer(line.Length * 2);
    }

    public static string StringEncryptionLevelFour(string line)
    {
      if (Instance == IntPtr.Zero)
        Instance = CreateInstance();
      return StringEncryptionLevelOne(Instance, line.ToPointer(), line.Length).StringFromPointer(line.Length * 2);
    }

    public static void ClearEncryptionLevelFour()
    {
      if (Instance == IntPtr.Zero)
        Instance = CreateInstance();
      ClearEncryptionLevelFour(Instance);
    }
  }
}
