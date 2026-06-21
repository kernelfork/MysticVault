using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Threading;

namespace MysticVault;

public static class AntiDebug
{
    [DllImport("kernel32.dll", ExactSpelling = true, SetLastError = true)]
    private static extern bool CheckRemoteDebuggerPresent(IntPtr hProcess, ref bool isDebuggerPresent);

    [DllImport("kernel32.dll", ExactSpelling = true, SetLastError = true)]
    private static extern bool IsDebuggerPresent();

    [DllImport("ntdll.dll", SetLastError = true)]
    private static extern int NtQueryInformationProcess(IntPtr processHandle, int processInformationClass, ref IntPtr processInformation, int processInformationLength, out int returnLength);

    [DllImport("ntdll.dll", SetLastError = true)]
    private static extern int NtSetInformationThread(IntPtr threadHandle, int threadInformationClass, IntPtr threadInformation, int threadInformationLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr GetCurrentThread();

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenThread(uint desiredAccess, bool inheritHandle, uint threadId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetThreadContext(IntPtr hThread, ref CONTEXT lpContext);

    [StructLayout(LayoutKind.Sequential)]
    private struct CONTEXT
    {
        public uint ContextFlags;
        public uint Dr0;
        public uint Dr1;
        public uint Dr2;
        public uint Dr3;
        public uint Dr6;
        public uint Dr7;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 48)]
        public byte[] Unknown;
    }

    private const int ProcessDebugPort = 7;
    private const int ProcessDebugObjectHandle = 30;
    private const int ThreadHideFromDebugger = 17;
    private const uint CONTEXT_DEBUG_REGISTERS = 0x00010010;
    private const uint THREAD_GET_CONTEXT = 0x0008;

    public static void Initialize()
    {
        NtSetInformationThread(GetCurrentThread(), ThreadHideFromDebugger, IntPtr.Zero, 0);

        var thread = new Thread(AntiDebugLoop)
        {
            IsBackground = true,
            Name = "AntiDebugMonitor"
        };
        thread.Start();
    }

    private static void AntiDebugLoop()
    {
        while (true)
        {
            bool isDebuggerPresent = false;
            CheckRemoteDebuggerPresent(Process.GetCurrentProcess().Handle, ref isDebuggerPresent);

            if (IsDebuggerPresent() || isDebuggerPresent || Debugger.IsAttached)
            {
                Environment.FailFast("CRITICAL SECURITY VIOLATION: Debugger detected.");
            }

            IntPtr debugPort = IntPtr.Zero;
            NtQueryInformationProcess(Process.GetCurrentProcess().Handle, ProcessDebugPort, ref debugPort, IntPtr.Size, out _);
            if (debugPort != IntPtr.Zero)
            {
                Environment.FailFast("CRITICAL SECURITY VIOLATION: Kernel Debug Port detected.");
            }

            IntPtr debugObject = IntPtr.Zero;
            NtQueryInformationProcess(Process.GetCurrentProcess().Handle, ProcessDebugObjectHandle, ref debugObject, IntPtr.Size, out _);
            if (debugObject != IntPtr.Zero)
            {
                Environment.FailFast("CRITICAL SECURITY VIOLATION: Debug Object Handle detected.");
            }

            foreach (ProcessThread pt in Process.GetCurrentProcess().Threads)
            {
                IntPtr hThread = OpenThread(THREAD_GET_CONTEXT, false, (uint)pt.Id);
                if (hThread != IntPtr.Zero)
                {
                    CONTEXT ctx = new CONTEXT();
                    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
                    if (GetThreadContext(hThread, ref ctx))
                    {
                        if (ctx.Dr0 != 0 || ctx.Dr1 != 0 || ctx.Dr2 != 0 || ctx.Dr3 != 0)
                        {
                            Environment.FailFast("CRITICAL SECURITY VIOLATION: Hardware Breakpoint detected on CPU.");
                        }
                    }
                }
            }

            Thread.Sleep(1000);
        }
    }
}
