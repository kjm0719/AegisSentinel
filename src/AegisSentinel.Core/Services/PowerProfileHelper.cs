using System.Runtime.InteropServices;

namespace AegisSentinel.Core.Services;

/// <summary>
/// Zero-allocation Win32 battery/power status detector so AegisSentinel automatically
/// reduces background polling wakeups and disk snapshots when running on laptop battery power
/// while keeping real-time kernel ETW threat interception 100% active.
/// </summary>
public static class PowerProfileHelper
{
    [StructLayout(LayoutKind.Sequential)]
    private struct SYSTEM_POWER_STATUS
    {
        public byte ACLineStatus;       // 0 = Offline (Battery), 1 = Online (AC), 255 = Unknown
        public byte BatteryFlag;
        public byte BatteryLifePercent;
        public byte SystemStatusFlag;   // 1 = Windows Battery Saver ON
        public uint BatteryLifeTime;
        public uint BatteryFullLifeTime;
    }

    [DllImport("kernel32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetSystemPowerStatus(out SYSTEM_POWER_STATUS lpSystemPowerStatus);

    public static bool IsOnBatteryPower
    {
        get
        {
            try
            {
                return GetSystemPowerStatus(out var status) && status.ACLineStatus == 0;
            }
            catch
            {
                return false;
            }
        }
    }

    public static bool IsBatterySaverActive
    {
        get
        {
            try
            {
                return GetSystemPowerStatus(out var status) && status.SystemStatusFlag == 1;
            }
            catch
            {
                return false;
            }
        }
    }
}
