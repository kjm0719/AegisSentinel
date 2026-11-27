using System.Runtime.InteropServices;
using System.Text;

namespace AegisSentinel.Core.Services;

public sealed record ParsedShellLink(
    string TargetPath,
    string Arguments,
    string Description,
    string WorkingDirectory,
    string IconLocation);

/// <summary>
/// Pure C# [MS-SHLLINK] (.lnk) binary structure parser.
/// Strictly separates LinkInfo/RelativePath/EnvironmentVariableDataBlock TargetPath from
/// StringData fields (Name/Description, RelativePath, WorkingDir, CommandLineArguments, IconLocation)
/// so strings in icon paths or descriptions are never misread as command-line arguments.
/// </summary>
public static class ShellLinkParser
{
    private const uint ShellLinkHeaderSize = 0x0000004C;
    private static readonly byte[] ShellLinkClsid =
    {
        0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46
    };

    private const uint FlagHasLinkTargetIdList = 0x00000001;
    private const uint FlagHasLinkInfo = 0x00000002;
    private const uint FlagHasName = 0x00000004;
    private const uint FlagHasRelativePath = 0x00000008;
    private const uint FlagHasWorkingDir = 0x00000010;
    private const uint FlagHasArguments = 0x00000020;
    private const uint FlagHasIconLocation = 0x00000040;
    private const uint FlagIsUnicode = 0x00000080;

    private const uint LinkInfoFlagVolumeIdAndLocalBasePath = 0x00000001;
    private const uint EnvVarBlockSignature = 0xA0000001;
    private const uint CP_ACP = 0;

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = false)]
    private static extern int MultiByteToWideChar(
        uint codePage,
        uint dwFlags,
        [In] byte[] lpMultiByteStr,
        int cbMultiByte,
        [Out] char[]? lpWideCharStr,
        int cchWideChar);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = false)]
    private static extern int WideCharToMultiByte(
        uint codePage,
        uint dwFlags,
        [MarshalAs(UnmanagedType.LPWStr)] string lpWideCharStr,
        int cchWideChar,
        [Out] byte[]? lpMultiByteStr,
        int cbMultiByte,
        IntPtr lpDefaultChar,
        IntPtr lpUsedDefaultChar);

    public static bool TryParseFile(string lnkPath, out ParsedShellLink? parsed)
    {
        parsed = null;
        try
        {
            if (string.IsNullOrWhiteSpace(lnkPath) || !File.Exists(lnkPath))
            {
                return false;
            }
            var fullLnkPath = Path.GetFullPath(lnkPath);
            var baseDir = Path.GetDirectoryName(fullLnkPath);
            var raw = File.ReadAllBytes(fullLnkPath);
            return TryParseBytes(raw, out parsed, baseDir);
        }
        catch
        {
            return false;
        }
    }

    public static bool TryParseBytes(ReadOnlySpan<byte> raw, out ParsedShellLink? parsed, string? baseDirectory = null)
    {
        parsed = null;
        if (raw.Length < ShellLinkHeaderSize)
        {
            return false;
        }

        uint headerSize = BitConverter.ToUInt32(raw[..4]);
        if (headerSize != ShellLinkHeaderSize)
        {
            return false;
        }

        if (!raw.Slice(4, 16).SequenceEqual(ShellLinkClsid))
        {
            return false;
        }

        uint linkFlags = BitConverter.ToUInt32(raw.Slice(20, 4));
        bool isUnicode = (linkFlags & FlagIsUnicode) != 0;

        int offset = (int)ShellLinkHeaderSize;

        // 1. Optional LinkTargetIDList
        if ((linkFlags & FlagHasLinkTargetIdList) != 0)
        {
            if (offset + 2 > raw.Length) return false;
            ushort idListSize = BitConverter.ToUInt16(raw.Slice(offset, 2));
            offset += 2;
            if (offset + idListSize > raw.Length) return false;
            offset += idListSize;
        }

        // 2. Optional LinkInfo -> LocalBasePath + CommonPathSuffix
        string targetPath = string.Empty;
        if ((linkFlags & FlagHasLinkInfo) != 0)
        {
            if (offset + 4 > raw.Length) return false;
            uint linkInfoSize = BitConverter.ToUInt32(raw.Slice(offset, 4));
            if (linkInfoSize < 28 || offset + linkInfoSize > raw.Length) return false;

            var linkInfo = raw.Slice(offset, (int)linkInfoSize);
            targetPath = ParseTargetPathFromLinkInfo(linkInfo);
            offset += (int)linkInfoSize;
        }

        // 3. Optional StringData (strict MS-SHLLINK order)
        string description = string.Empty;
        string relativePath = string.Empty;
        string workingDir = string.Empty;
        string arguments = string.Empty;
        string iconLocation = string.Empty;

        if ((linkFlags & FlagHasName) != 0 && !TryReadCountedString(raw, ref offset, isUnicode, out description))
        {
            return false;
        }
        if ((linkFlags & FlagHasRelativePath) != 0 && !TryReadCountedString(raw, ref offset, isUnicode, out relativePath))
        {
            return false;
        }
        if ((linkFlags & FlagHasWorkingDir) != 0 && !TryReadCountedString(raw, ref offset, isUnicode, out workingDir))
        {
            return false;
        }
        if ((linkFlags & FlagHasArguments) != 0 && !TryReadCountedString(raw, ref offset, isUnicode, out arguments))
        {
            return false;
        }
        if ((linkFlags & FlagHasIconLocation) != 0 && !TryReadCountedString(raw, ref offset, isUnicode, out iconLocation))
        {
            return false;
        }

        // 4. Optional ExtraData blocks (e.g., EnvironmentVariableDataBlock when LinkInfo absent)
        if (string.IsNullOrWhiteSpace(targetPath))
        {
            var envTarget = TryExtractEnvironmentTargetFromExtraData(raw, offset);
            if (!string.IsNullOrWhiteSpace(envTarget))
            {
                targetPath = Environment.ExpandEnvironmentVariables(envTarget);
            }
        }

        if (string.IsNullOrWhiteSpace(targetPath) && !string.IsNullOrWhiteSpace(relativePath))
        {
            if (!string.IsNullOrWhiteSpace(baseDirectory) && !Path.IsPathRooted(relativePath))
            {
                try
                {
                    targetPath = Path.GetFullPath(Path.Combine(baseDirectory, relativePath));
                }
                catch
                {
                    targetPath = relativePath;
                }
            }
            else
            {
                targetPath = relativePath;
            }
        }

        parsed = new ParsedShellLink(
            targetPath.Trim(),
            arguments.Trim(),
            description.Trim(),
            workingDir.Trim(),
            iconLocation.Trim());
        return true;
    }

    private static string ParseTargetPathFromLinkInfo(ReadOnlySpan<byte> linkInfo)
    {
        uint headerSize = BitConverter.ToUInt32(linkInfo.Slice(4, 4));
        uint linkInfoFlags = BitConverter.ToUInt32(linkInfo.Slice(8, 4));
        if ((linkInfoFlags & LinkInfoFlagVolumeIdAndLocalBasePath) == 0)
        {
            return string.Empty;
        }

        if (headerSize >= 0x24 && linkInfo.Length >= 0x24)
        {
            uint localBasePathUnicodeOffset = BitConverter.ToUInt32(linkInfo.Slice(28, 4));
            uint commonPathSuffixUnicodeOffset = BitConverter.ToUInt32(linkInfo.Slice(32, 4));
            var baseUni = ReadNullTerminatedUnicode(linkInfo, (int)localBasePathUnicodeOffset);
            var suffixUni = ReadNullTerminatedUnicode(linkInfo, (int)commonPathSuffixUnicodeOffset);
            if (!string.IsNullOrWhiteSpace(baseUni))
            {
                return string.IsNullOrWhiteSpace(suffixUni) ? baseUni : CombineBaseAndSuffix(baseUni, suffixUni);
            }
        }

        uint localBasePathOffset = BitConverter.ToUInt32(linkInfo.Slice(16, 4));
        uint commonPathSuffixOffset = BitConverter.ToUInt32(linkInfo.Slice(24, 4));
        var baseAnsi = ReadNullTerminatedAnsi(linkInfo, (int)localBasePathOffset);
        var suffixAnsi = ReadNullTerminatedAnsi(linkInfo, (int)commonPathSuffixOffset);
        if (string.IsNullOrWhiteSpace(baseAnsi))
        {
            return string.Empty;
        }
        return string.IsNullOrWhiteSpace(suffixAnsi) ? baseAnsi : CombineBaseAndSuffix(baseAnsi, suffixAnsi);
    }

    private static string CombineBaseAndSuffix(string basePath, string suffix)
    {
        if (basePath.EndsWith('\\') || suffix.StartsWith('\\'))
        {
            return basePath + suffix;
        }
        return basePath + "\\" + suffix;
    }

    private static string TryExtractEnvironmentTargetFromExtraData(ReadOnlySpan<byte> raw, int offset)
    {
        while (offset + 4 <= raw.Length)
        {
            uint blockSize = BitConverter.ToUInt32(raw.Slice(offset, 4));
            if (blockSize < 4)
            {
                break; // TerminalBlock
            }
            if (offset + blockSize > raw.Length)
            {
                break;
            }
            if (blockSize >= 788)
            {
                uint signature = BitConverter.ToUInt32(raw.Slice(offset + 4, 4));
                if (signature == EnvVarBlockSignature)
                {
                    var block = raw.Slice(offset, (int)blockSize);
                    var uni = ReadNullTerminatedUnicode(block, 268);
                    if (!string.IsNullOrWhiteSpace(uni)) return uni;
                    var ansi = ReadNullTerminatedAnsi(block, 8);
                    if (!string.IsNullOrWhiteSpace(ansi)) return ansi;
                }
            }
            offset += (int)blockSize;
        }
        return string.Empty;
    }

    private static bool TryReadCountedString(ReadOnlySpan<byte> raw, ref int offset, bool isUnicode, out string value)
    {
        value = string.Empty;
        if (offset + 2 > raw.Length) return false;
        ushort charCount = BitConverter.ToUInt16(raw.Slice(offset, 2));
        offset += 2;
        int byteLen = isUnicode ? charCount * 2 : charCount;
        if (offset + byteLen > raw.Length) return false;
        var slice = raw.Slice(offset, byteLen);
        value = isUnicode ? Encoding.Unicode.GetString(slice) : DecodeWindowsAnsi(slice);
        offset += byteLen;
        return true;
    }

    private static string ReadNullTerminatedAnsi(ReadOnlySpan<byte> span, int offset)
    {
        if (offset <= 0 || offset >= span.Length) return string.Empty;
        int end = offset;
        while (end < span.Length && span[end] != 0) end++;
        return end > offset ? DecodeWindowsAnsi(span.Slice(offset, end - offset)) : string.Empty;
    }

    /// <summary>
    /// Decodes a Windows ANSI (CP_ACP, e.g. CP949/CP1252) byte span natively via Win32 MultiByteToWideChar
    /// instead of Encoding.Default (which is UTF-8 in .NET Core/.NET 10 and corrupts non-ASCII paths).
    /// </summary>
    public static string DecodeWindowsAnsi(ReadOnlySpan<byte> bytes)
    {
        if (bytes.IsEmpty) return string.Empty;
        var buf = bytes.ToArray();
        int wideLen = MultiByteToWideChar(CP_ACP, 0, buf, buf.Length, null, 0);
        if (wideLen <= 0)
        {
            return Encoding.UTF8.GetString(buf);
        }
        var chars = new char[wideLen];
        int written = MultiByteToWideChar(CP_ACP, 0, buf, buf.Length, chars, chars.Length);
        return written > 0 ? new string(chars, 0, written) : Encoding.UTF8.GetString(buf);
    }

    public static byte[] EncodeWindowsAnsi(string text)
    {
        if (string.IsNullOrEmpty(text)) return Array.Empty<byte>();
        int byteLen = WideCharToMultiByte(CP_ACP, 0, text, text.Length, null, 0, IntPtr.Zero, IntPtr.Zero);
        if (byteLen <= 0)
        {
            return Encoding.UTF8.GetBytes(text);
        }
        var bytes = new byte[byteLen];
        int written = WideCharToMultiByte(CP_ACP, 0, text, text.Length, bytes, bytes.Length, IntPtr.Zero, IntPtr.Zero);
        return written > 0 ? bytes[..written] : Encoding.UTF8.GetBytes(text);
    }

    private static string ReadNullTerminatedUnicode(ReadOnlySpan<byte> span, int offset)
    {
        if (offset <= 0 || offset + 1 >= span.Length) return string.Empty;
        int end = offset;
        while (end + 1 < span.Length && !(span[end] == 0 && span[end + 1] == 0))
        {
            end += 2;
        }
        return end > offset ? Encoding.Unicode.GetString(span.Slice(offset, end - offset)) : string.Empty;
    }

    /// <summary>
    /// Builds a valid [MS-SHLLINK] binary shortcut with Unicode LinkInfo + StringData fields.
    /// Useful for deterministic tests without requiring Windows Shell COM side effects.
    /// </summary>
    public static byte[] BuildSimpleShortcutBytes(
        string targetPath,
        string arguments = "",
        string description = "",
        string workingDirectory = "",
        string iconLocation = "")
    {
        using var ms = new MemoryStream();
        using var bw = new BinaryWriter(ms, Encoding.Unicode, leaveOpen: true);

        uint flags = FlagIsUnicode;
        if (!string.IsNullOrEmpty(targetPath)) flags |= FlagHasLinkInfo;
        if (!string.IsNullOrEmpty(description)) flags |= FlagHasName;
        if (!string.IsNullOrEmpty(workingDirectory)) flags |= FlagHasWorkingDir;
        if (!string.IsNullOrEmpty(arguments)) flags |= FlagHasArguments;
        if (!string.IsNullOrEmpty(iconLocation)) flags |= FlagHasIconLocation;

        // 76-byte ShellLinkHeader
        bw.Write(ShellLinkHeaderSize);
        bw.Write(ShellLinkClsid);
        bw.Write(flags);
        bw.Write(new byte[76 - 24]);

        // LinkInfo with Unicode LocalBasePath
        if ((flags & FlagHasLinkInfo) != 0)
        {
            var ansiTarget = Encoding.ASCII.GetBytes(targetPath + "\0");
            var uniTarget = Encoding.Unicode.GetBytes(targetPath + "\0");
            const uint linkInfoHeaderSize = 0x24;
            uint localBasePathOffset = linkInfoHeaderSize;
            uint commonSuffixOffset = localBasePathOffset + (uint)ansiTarget.Length;
            uint localBasePathUnicodeOffset = commonSuffixOffset + 1; // 1 byte '\0'
            uint commonSuffixUnicodeOffset = localBasePathUnicodeOffset + (uint)uniTarget.Length;
            uint linkInfoSize = commonSuffixUnicodeOffset + 2; // 2 bytes '\0\0'

            bw.Write(linkInfoSize);
            bw.Write(linkInfoHeaderSize);
            bw.Write(LinkInfoFlagVolumeIdAndLocalBasePath);
            bw.Write(0u); // VolumeIDOffset
            bw.Write(localBasePathOffset);
            bw.Write(0u); // CommonNetworkRelativeLinkOffset
            bw.Write(commonSuffixOffset);
            bw.Write(localBasePathUnicodeOffset);
            bw.Write(commonSuffixUnicodeOffset);
            bw.Write(ansiTarget);
            bw.Write((byte)0);
            bw.Write(uniTarget);
            bw.Write((ushort)0);
        }

        static void WriteUnicodeStringData(BinaryWriter writer, string text)
        {
            writer.Write((ushort)text.Length);
            writer.Write(Encoding.Unicode.GetBytes(text));
        }

        if ((flags & FlagHasName) != 0) WriteUnicodeStringData(bw, description);
        if ((flags & FlagHasWorkingDir) != 0) WriteUnicodeStringData(bw, workingDirectory);
        if ((flags & FlagHasArguments) != 0) WriteUnicodeStringData(bw, arguments);
        if ((flags & FlagHasIconLocation) != 0) WriteUnicodeStringData(bw, iconLocation);

        // TerminalBlock
        bw.Write(0u);
        bw.Flush();
        return ms.ToArray();
    }
}
