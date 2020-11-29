using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;

namespace GameWer.Helper
{
  public static class Extenstions
  {
    public static GetPacketID_Delegate GetPacketIDHandler;
    public static GetPacketID_Delegate ClearPacketIDHandler;

    public static IntPtr ToPointer(this string line)
    {
      var bytes = Encoding.UTF8.GetBytes(line);
      var destination = Marshal.AllocHGlobal(bytes.Length);
      Marshal.Copy(bytes, 0, destination, bytes.Length);
      return destination;
    }

    public static string StringFromPointer(this IntPtr pointer, int size)
    {
      var destination = new byte[size];
      Marshal.Copy(pointer, destination, 0, size);
      return destination.ToArray<byte>().BufferToUTF8();
    }

    public static void FreePointer(this IntPtr pointer)
    {
      Marshal.FreeHGlobal(pointer);
    }

    public static string BufferToUTF8(this byte[] buffer)
    {
      return Encoding.UTF8.GetString(buffer);
    }

    public delegate string GetPacketID_Delegate();
  }
}
