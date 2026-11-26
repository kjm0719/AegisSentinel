using System.Net;
using System.Text;
using System.Text.Json;
using AegisSentinel.Core.Models;

namespace AegisSentinel.Core.Services;

/// <summary>
/// Persists structured security events to daily JSONL audit logs and exports standalone
/// HTML forensic incident reports with MITRE ATT&amp;CK mappings.
/// </summary>
public sealed class AuditLogService
{
    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = false };
    private readonly object _sync = new();

    public string LogsDirectory { get; }

    public AuditLogService(string? baseDirectory = null)
    {
        var root = baseDirectory ?? Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "AegisSentinel");
        LogsDirectory = Path.Combine(root, "Logs");
        Directory.CreateDirectory(LogsDirectory);
    }

    public void Append(SecurityEvent evt)
    {
        try
        {
            evt.EnsureMitrePopulated();
            evt.SchemaVersion = SecurityEvent.CurrentSchemaVersion;
            var logPath = Path.Combine(LogsDirectory, $"events-{DateTime.Now:yyyyMMdd}.jsonl");
            var line = JsonSerializer.Serialize(evt, JsonOptions) + Environment.NewLine;
            lock (_sync)
            {
                File.AppendAllText(logPath, line, Encoding.UTF8);
            }
        }
        catch
        {
            // Keep logging resilient.
        }
    }

    public IReadOnlyList<SecurityEvent> LoadRecentEvents(int maxCount = 200)
    {
        var results = new List<SecurityEvent>();
        if (!Directory.Exists(LogsDirectory))
        {
            return results;
        }

        try
        {
            var files = Directory.GetFiles(LogsDirectory, "events-*.jsonl")
                .OrderByDescending(f => f)
                .Take(7);

            foreach (var file in files)
            {
                var lines = new List<string>();
                using (var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
                using (var sr = new StreamReader(fs, Encoding.UTF8))
                {
                    while (sr.ReadLine() is { } line)
                    {
                        lines.Add(line);
                        if (lines.Count > 5000) lines.RemoveAt(0);
                    }
                }

                for (int i = lines.Count - 1; i >= 0 && results.Count < maxCount; i--)
                {
                    if (string.IsNullOrWhiteSpace(lines[i])) continue;
                    try
                    {
                        var evt = JsonSerializer.Deserialize<SecurityEvent>(lines[i]);
                        if (evt is not null)
                        {
                            evt.EnsureMitrePopulated();
                            results.Add(evt);
                        }
                    }
                    catch { }
                }

                if (results.Count >= maxCount) break;
            }
        }
        catch { }

        return results;
    }

    public string ExportMitreNavigatorLayer(IReadOnlyList<SecurityEvent> events, string? outputPath = null)
    {
        var path = outputPath ?? Path.Combine(LogsDirectory, $"AegisSentinel_ATTACK_Layer_{DateTime.Now:yyyyMMdd_HHmmss}.json");
        var dir = Path.GetDirectoryName(path);
        if (!string.IsNullOrEmpty(dir))
        {
            Directory.CreateDirectory(dir);
        }

        var json = MitreAttackCatalog.ExportNavigatorLayerJson(events);
        File.WriteAllText(path, json, Encoding.UTF8);
        return path;
    }

    public string ExportHtmlReport(
        IReadOnlyList<SecurityEvent> events,
        HardeningStatus? hardening,
        IReadOnlyList<QuarantineEntry> quarantine,
        IReadOnlyList<VaultSnapshotEntry> vaultSnapshots,
        string? outputPath = null,
        TelemetrySnapshot? telemetry = null)
    {
        var path = outputPath ?? Path.Combine(LogsDirectory, $"AegisSentinel_Report_{DateTime.Now:yyyyMMdd_HHmmss}.html");
        var dir = Path.GetDirectoryName(path);
        if (!string.IsNullOrEmpty(dir))
        {
            Directory.CreateDirectory(dir);
        }

        var sb = new StringBuilder();
        sb.AppendLine("<!DOCTYPE html>");
        sb.AppendLine("<html lang=\"ko\"><head><meta charset=\"utf-8\"/>");
        sb.AppendLine("<title>AegisSentinel 포렌식 보안 리포트</title>");
        sb.AppendLine("<style>");
        sb.AppendLine("body{font-family:'Segoe UI',sans-serif;background:#0b111a;color:#e2e8f0;margin:0;padding:28px;}");
        sb.AppendLine("h1,h2{color:#38bdf8;margin-top:24px;} .card{background:#131c2a;border:1px solid #263449;border-radius:10px;padding:18px;margin-bottom:16px;}");
        sb.AppendLine("table{width:100%;border-collapse:collapse;font-size:13px;} th,td{border-bottom:1px solid #263449;padding:8px 10px;text-align:left;vertical-align:top;}");
        sb.AppendLine("th{background:#1b2638;color:#93c5fd;} .crit{color:#fca5a5;font-weight:bold;} .high{color:#fdba74;font-weight:bold;} .med{color:#fde047;}");
        sb.AppendLine(".badge{display:inline-block;padding:3px 8px;border-radius:6px;background:#1e293b;color:#38bdf8;font-size:12px;}");
        sb.AppendLine("</style></head><body>");

        sb.AppendLine("<h1>AegisSentinel 엔드포인트 포렌식 보안 리포트</h1>");
        sb.AppendLine($"<p>생성 시각: {DateTime.Now:yyyy-MM-dd HH:mm:ss} | 호스트: {WebUtility.HtmlEncode(Environment.MachineName)} | 사용자: {WebUtility.HtmlEncode(Environment.UserName)}</p>");

        sb.AppendLine("<div class=\"card\"><h2>1. 시스템 보안 태세 요약</h2>");
        if (hardening is not null)
        {
            sb.AppendLine($"<p><strong>OS 종합 보안 점수:</strong> <span class=\"badge\">{hardening.SecurityPostureScore} / 100</span></p>");
            sb.AppendLine($"<p>Defender 실시간: {(hardening.DefenderRealTimeEnabled ? "ON" : "OFF")} | 변조방지: {(hardening.TamperProtectionEnabled ? "ON" : "OFF")} | 커널폴더보호(CFA): {(hardening.ControlledFolderAccessEnabled ? "ON" : "OFF")} | 메모리무결성(HVCI): {(hardening.MemoryIntegrityHvciEnabled ? "ON" : "OFF")} | ASR 규칙: {hardening.ActiveAsrRuleCount}개</p>");
        }
        sb.AppendLine($"<p>기록된 위협 이벤트: <strong>{events.Count}건</strong> | 격리된 파일: <strong>{quarantine.Count}건</strong> | 복구 금고 스냅샷: <strong>{vaultSnapshots.Count}건</strong> | MITRE ATT&amp;CK 커버리지: <strong>{MitreAttackCatalog.GetAllCoveredTechniques().Count}개 기법</strong></p>");
        if (telemetry is not null)
        {
            sb.AppendLine($"<p><strong>실시간 ETW 텔레메트리:</strong> 총 {telemetry.TotalTelemetryEvents:N0}건 (프로세스 {telemetry.ProcessEvents:N0} · 파일 {telemetry.FileEvents:N0} · 네트워크 {telemetry.NetworkEvents:N0} · DNS {telemetry.DnsEvents:N0} · 레지스트리 {telemetry.RegistryEvents:N0}) | 평균 규칙 평가 지연: <strong>{telemetry.AverageEvalMicroseconds:F2} µs</strong> | 프로세스 동결: {telemetry.ProcessesFrozen}건</p>");
        }
        sb.AppendLine("</div>");

        sb.AppendLine("<div class=\"card\"><h2>2. 탐지된 보안 이벤트 &amp; MITRE ATT&amp;CK 매핑</h2>");
        sb.AppendLine("<table><thead><tr><th>시각</th><th>심각도</th><th>위험도</th><th>MITRE</th><th>프로세스 / 계보</th><th>제목 및 상세</th><th>조치</th></tr></thead><tbody>");
        foreach (var e in events)
        {
            e.EnsureMitrePopulated();
            var cls = e.Severity switch
            {
                ThreatSeverity.Critical => "crit",
                ThreatSeverity.High => "high",
                _ => "med"
            };
            var procCol = WebUtility.HtmlEncode(string.IsNullOrWhiteSpace(e.ProcessAncestry)
                ? $"{e.ProcessName} ({e.ProcessId})"
                : e.ProcessAncestry);
            var detail = WebUtility.HtmlEncode($"{e.Title} — {e.Description}");
            if (!string.IsNullOrWhiteSpace(e.RemoteEndpoint))
            {
                detail += $"<br/><small>원격: {WebUtility.HtmlEncode(e.RemoteEndpoint)} {WebUtility.HtmlEncode(e.RemoteDomain)}</small>";
            }

            sb.AppendLine($"<tr><td>{e.Timestamp:yyyy-MM-dd HH:mm:ss}</td><td class=\"{cls}\">{e.Severity}</td><td>{e.RiskScore}/100</td><td><span class=\"badge\">{WebUtility.HtmlEncode(e.MitreTechniqueId)}</span></td><td>{procCol}</td><td>{detail}</td><td>{e.ActionTaken}</td></tr>");
        }
        sb.AppendLine("</tbody></table></div>");

        if (quarantine.Count > 0)
        {
            sb.AppendLine("<div class=\"card\"><h2>3. 격리된 파일 목록</h2><table><thead><tr><th>격리 시각</th><th>원본 경로</th><th>사유</th><th>SHA-256</th></tr></thead><tbody>");
            foreach (var q in quarantine)
            {
                sb.AppendLine($"<tr><td>{q.QuarantinedAt:yyyy-MM-dd HH:mm}</td><td>{WebUtility.HtmlEncode(q.OriginalPath)}</td><td>{WebUtility.HtmlEncode(q.Reason)}</td><td><code>{WebUtility.HtmlEncode(q.Sha256)}</code></td></tr>");
            }
            sb.AppendLine("</tbody></table></div>");
        }

        sb.AppendLine("</body></html>");
        File.WriteAllText(path, sb.ToString(), Encoding.UTF8);
        return path;
    }
}
