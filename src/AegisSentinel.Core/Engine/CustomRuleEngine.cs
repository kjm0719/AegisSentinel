using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using AegisSentinel.Core.Models;
using AegisSentinel.Core.Services;

namespace AegisSentinel.Core.Engine;

/// <summary>
/// Declarative Detection-as-Code (Sigma-style JSON) rule schema that allows SOC analysts
/// and security engineers to author, hot-reload, and version-control custom detection rules
/// without recompiling the EDR engine.
/// </summary>
public sealed record DetectionRule
{
    public string Id { get; init; } = string.Empty;
    public string Name { get; init; } = string.Empty;
    public string Description { get; init; } = string.Empty;
    public string MitreTechniqueId { get; init; } = string.Empty;

    [JsonConverter(typeof(JsonStringEnumConverter))]
    public ThreatCategory Category { get; init; } = ThreatCategory.SupplyChain;

    [JsonConverter(typeof(JsonStringEnumConverter))]
    public ThreatSeverity Severity { get; init; } = ThreatSeverity.High;

    public int RiskScore { get; init; } = 80;
    public bool Enabled { get; init; } = true;
    public bool RequireUnsigned { get; init; }
    public string? ProcessNameRegex { get; init; }
    public string? ParentNameRegex { get; init; }
    public string? ProcessPathRegex { get; init; }
    public string? CommandLineRegex { get; init; }
}

/// <summary>
/// ReDoS-safe, lock-free snapshot-swapping Detection-as-Code rule evaluator backed by rules.json.
/// </summary>
public sealed class CustomRuleEngine
{
    private static readonly TimeSpan RegexTimeout = TimeSpan.FromMilliseconds(200);
    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true };

    private sealed record CompiledRule(
        DetectionRule Definition,
        Regex? ProcessName,
        Regex? ParentName,
        Regex? ProcessPath,
        Regex? CommandLine);

    private static readonly Regex CatastrophicQuantifierRegex = new(
        @"\([^)]*[+*][^)]*\)[+*]",
        RegexOptions.Compiled, TimeSpan.FromMilliseconds(200));

    private volatile IReadOnlyList<CompiledRule> _compiledRules = Array.Empty<CompiledRule>();
    private readonly object _fileSync = new();
    private readonly PolicyIntegritySigner _signer;

    public string RulesFilePath { get; }
    public int ActiveRuleCount => _compiledRules.Count;
    public bool LastLoadDetectedTampering { get; private set; }
    public string LastTamperReason { get; private set; } = string.Empty;

    public CustomRuleEngine(string? baseDirectory = null, PolicyIntegritySigner? sharedSigner = null)
    {
        var root = baseDirectory ?? Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "AegisSentinel");
        Directory.CreateDirectory(root);
        RulesFilePath = Path.Combine(root, "rules.json");
        _signer = sharedSigner ?? new PolicyIntegritySigner(root);
        LoadOrCreateDefaultRules();
    }

    public IReadOnlyList<DetectionRule> GetRulesSnapshot() =>
        _compiledRules.Select(r => r.Definition).ToList();

    public void SaveAndReload(IEnumerable<DetectionRule> rules)
    {
        var list = rules.Where(r => !string.IsNullOrWhiteSpace(r.Id) && !string.IsNullOrWhiteSpace(r.Name)).ToList();
        lock (_fileSync)
        {
            try
            {
                var tmp = RulesFilePath + $".{Guid.NewGuid():N}.tmp";
                File.WriteAllText(tmp, JsonSerializer.Serialize(list, JsonOptions));
                if (File.Exists(RulesFilePath))
                {
                    try { File.SetAttributes(RulesFilePath, FileAttributes.Normal); } catch { }
                }
                File.Move(tmp, RulesFilePath, overwrite: true);
                _signer.SignFile(RulesFilePath);
            }
            catch { }
            _compiledRules = CompileAll(list);
        }
    }

    public void Reload()
    {
        LoadOrCreateDefaultRules();
    }

    public bool VerifyIntegrity(out string reason)
    {
        lock (_fileSync)
        {
            return _signer.VerifyFile(RulesFilePath, out reason);
        }
    }

    public SecurityEvent? EvaluateProcess(ProcessEvaluationContext ctx, string ancestry = "")
    {
        var rules = _compiledRules;
        if (rules.Count == 0) return null;

        var procName = Path.GetFileName(string.IsNullOrWhiteSpace(ctx.ProcessPath) ? ctx.ProcessName : ctx.ProcessPath);
        var parentName = Path.GetFileName(string.IsNullOrWhiteSpace(ctx.ParentProcessPath) ? ctx.ParentProcessName : ctx.ParentProcessPath);

        DetectionRule? bestMatch = null;
        foreach (var rule in rules)
        {
            var def = rule.Definition;
            if (!def.Enabled) continue;
            if (def.RequireUnsigned && ctx.Signature.IsSigned) continue;

            if (rule.ProcessName is null && rule.ParentName is null && rule.ProcessPath is null && rule.CommandLine is null)
            {
                continue;
            }

            try
            {
                if (rule.ProcessName is not null && !rule.ProcessName.IsMatch(procName ?? string.Empty)) continue;
                if (rule.ParentName is not null && !rule.ParentName.IsMatch(parentName ?? string.Empty)) continue;
                if (rule.ProcessPath is not null && !rule.ProcessPath.IsMatch(ctx.ProcessPath ?? string.Empty)) continue;
                if (rule.CommandLine is not null && !rule.CommandLine.IsMatch(ctx.CommandLine ?? string.Empty)) continue;
            }
            catch (RegexMatchTimeoutException)
            {
                continue;
            }

            if (bestMatch is null || def.RiskScore > bestMatch.RiskScore)
            {
                bestMatch = def;
            }
        }

        if (bestMatch is null) return null;

        int clampedScore = Math.Clamp(bestMatch.RiskScore, 10, 100);
        return new SecurityEvent
        {
            Severity = bestMatch.Severity,
            Category = bestMatch.Category,
            ActionTaken = SecurityActionTaken.Logged,
            Title = $"[Custom Rule {bestMatch.Id}] {bestMatch.Name}",
            Description = bestMatch.Description,
            MitreTechniqueId = bestMatch.MitreTechniqueId,
            MitreTactic = MitreAttackCatalog.ResolveTacticById(bestMatch.MitreTechniqueId),
            ProcessId = ctx.ProcessId,
            ProcessName = ctx.ProcessName ?? string.Empty,
            ProcessPath = ctx.ProcessPath ?? string.Empty,
            ParentProcessId = ctx.ParentProcessId,
            ParentProcessName = ctx.ParentProcessName ?? string.Empty,
            ProcessAncestry = ancestry,
            CommandLine = ctx.CommandLine ?? string.Empty,
            TargetPath = ctx.ProcessPath ?? string.Empty,
            RiskScore = clampedScore,
            RiskSignals = new List<string> { $"CustomRule:{bestMatch.Id}(+{clampedScore})" },
            Signature = ctx.Signature
        };
    }

    public static List<DetectionRule> CreateDefaultRules() => new()
    {
        new DetectionRule
        {
            Id = "AEGIS-001",
            Name = "Certutil Base64/Hex 페이로드 디코딩 드로퍼",
            Description = "certutil.exe -decode/-decodehex 옵션으로 난독화된 악성 바이너리를 디스크에 복원하려는 시도가 탐지되었습니다.",
            MitreTechniqueId = "T1140",
            Category = ThreatCategory.Masquerading,
            Severity = ThreatSeverity.Critical,
            RiskScore = 85,
            ProcessNameRegex = @"^certutil(\.exe)?$",
            CommandLineRegex = @"\s[-/](decode|decodehex)\s+[^\r\n]{1,260}\.(exe|dll|ps1|vbs|bat|hta|bin)"
        },
        new DetectionRule
        {
            Id = "AEGIS-002",
            Name = "MSBuild 인라인 태스크 애플리케이션 화이트리스트 우회",
            Description = "MSBuild.exe가 임시/다운로드/공용 경로의 XML·CSPROJ 인라인 코드를 직접 실행하려 했습니다.",
            MitreTechniqueId = "T1127.001",
            Category = ThreatCategory.FilelessScript,
            Severity = ThreatSeverity.Critical,
            RiskScore = 85,
            ProcessNameRegex = @"^msbuild(\.exe)?$",
            CommandLineRegex = @"(AppData\\Local\\Temp|Users\\Public|Downloads|ProgramData)[^\r\n]{0,200}\.(xml|csproj|proj|txt)"
        },
        new DetectionRule
        {
            Id = "AEGIS-003",
            Name = "InstallUtil / RegAsm / RegSvcs 서명 바이너리 프록시 실행",
            Description = ".NET 시스템 도구(InstallUtil/RegAsm/RegSvcs)를 악용해 임시 경로의 어셈블리를 우회 실행하려 했습니다.",
            MitreTechniqueId = "T1218.004",
            Category = ThreatCategory.Masquerading,
            Severity = ThreatSeverity.Critical,
            RiskScore = 85,
            ProcessNameRegex = @"^(installutil|regasm|regsvcs)(\.exe)?$",
            CommandLineRegex = @"(AppData\\Local\\Temp|Users\\Public|Downloads|ProgramData|/logfile=\s*/LogToConsole=false)"
        },
        new DetectionRule
        {
            Id = "AEGIS-004",
            Name = "NTDS.dit / AD 자격증명 데이터베이스 덤프 시도",
            Description = "ntdsutil IFM 또는 볼륨 섀도 경로에서 Active Directory 자격증명 DB(ntds.dit)를 추출하려는 시도가 감지되었습니다.",
            MitreTechniqueId = "T1003.003",
            Category = ThreatCategory.CredentialAccess,
            Severity = ThreatSeverity.Critical,
            RiskScore = 95,
            CommandLineRegex = @"(ntdsutil(\.exe)?[^\r\n]{0,160}create\s+full|ac\s+i\s+ntds|GLOBALROOT\\Device\\HarddiskVolumeShadowCopy[^\r\n]{0,160}ntds\.dit)"
        },
        new DetectionRule
        {
            Id = "AEGIS-005",
            Name = "도메인 트러스트 / AD 정찰 도구 실행 (nltest / adfind)",
            Description = "침해 후 내부망 확산 단계에서 사용되는 도메인 트러스트 열거 명령이 감지되었습니다.",
            MitreTechniqueId = "T1482",
            Category = ThreatCategory.PrivilegeEscalation,
            Severity = ThreatSeverity.High,
            RiskScore = 75,
            ProcessNameRegex = @"^(nltest|adfind)(\.exe)?$",
            CommandLineRegex = @"([-/]domain_trusts|[-/]all_trusts|[-/]dclist:|objectcategory=person)"
        },
        new DetectionRule
        {
            Id = "AEGIS-006",
            Name = "임시 경로 미서명 실행파일의 방화벽·보안정책 조작 시도",
            Description = "임시/공용 경로에서 실행된 미서명 바이너리가 Windows 방화벽 또는 보안 설정을 변경하려 했습니다.",
            MitreTechniqueId = "T1562.004",
            Category = ThreatCategory.SystemIntegrityTamper,
            Severity = ThreatSeverity.Critical,
            RiskScore = 90,
            RequireUnsigned = true,
            ProcessPathRegex = @"\\(Temp|Downloads|Users\\Public|ProgramData)\\",
            CommandLineRegex = @"(advfirewall|DisableRealtimeMonitoring|TamperProtection|EnableLUA)"
        }
    };

    private void LoadOrCreateDefaultRules()
    {
        lock (_fileSync)
        {
            LastLoadDetectedTampering = false;
            LastTamperReason = string.Empty;

            try
            {
                if (File.Exists(RulesFilePath))
                {
                    if (!_signer.VerifyFile(RulesFilePath, out var reason))
                    {
                        // Sharp-Edge Fail-Closed Self-Defense: restore hardened default SOC rules on tampering!
                        LastLoadDetectedTampering = true;
                        LastTamperReason = reason;
                    }
                    else
                    {
                        var loaded = JsonSerializer.Deserialize<List<DetectionRule>>(File.ReadAllText(RulesFilePath));
                        if (loaded is { Count: > 0 })
                        {
                            if (!File.Exists(RulesFilePath + ".hmac"))
                            {
                                _signer.SignFile(RulesFilePath);
                            }
                            _compiledRules = CompileAll(loaded);
                            return;
                        }
                    }
                }
            }
            catch { }

            var defaults = CreateDefaultRules();
            try
            {
                if (File.Exists(RulesFilePath))
                {
                    try { File.SetAttributes(RulesFilePath, FileAttributes.Normal); } catch { }
                }
                File.WriteAllText(RulesFilePath, JsonSerializer.Serialize(defaults, JsonOptions));
                _signer.SignFile(RulesFilePath);
            }
            catch { }
            _compiledRules = CompileAll(defaults);
        }
    }

    private static IReadOnlyList<CompiledRule> CompileAll(IEnumerable<DetectionRule> rules)
    {
        var compiled = new List<CompiledRule>();
        foreach (var r in rules)
        {
            if (r is null || string.IsNullOrWhiteSpace(r.Id) || string.IsNullOrWhiteSpace(r.Name)) continue;
            try
            {
                compiled.Add(new CompiledRule(
                    r,
                    CompileOptional(r.ProcessNameRegex),
                    CompileOptional(r.ParentNameRegex),
                    CompileOptional(r.ProcessPathRegex),
                    CompileOptional(r.CommandLineRegex)));
            }
            catch
            {
                // Skip invalid or catastrophic ReDoS regex gracefully without breaking other rules
            }
        }
        return compiled;
    }

    private static Regex? CompileOptional(string? pattern)
    {
        if (string.IsNullOrWhiteSpace(pattern)) return null;
        if (CatastrophicQuantifierRegex.IsMatch(pattern))
        {
            throw new ArgumentException($"Catastrophic ReDoS quantifier rejected in custom rule regex: {pattern}");
        }
        // Use .NET 10 RegexOptions.NonBacktracking for linear O(n) ReDoS-free matching, with safe 200ms-bounded fallback
        // if a user-authored custom rule uses lookarounds/backreferences unsupported by NonBacktracking.
        try
        {
            return new Regex(pattern, RegexOptions.IgnoreCase | RegexOptions.NonBacktracking, RegexTimeout);
        }
        catch (NotSupportedException)
        {
            return new Regex(pattern, RegexOptions.IgnoreCase | RegexOptions.Compiled, RegexTimeout);
        }
    }
}
