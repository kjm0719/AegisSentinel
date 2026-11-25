# AegisSentinel Enterprise — MITRE ATT&CK 커버리지 매트릭스 (40개 기법 · 11개 전술)

이 문서는 [MitreAttackCatalog.cs](file:///c:/Coding/AegisSentinel/src/AegisSentinel.Core/Models/MitreAttackCatalog.cs)에 정의된 **40개 MITRE ATT&CK Enterprise (Windows) 기법**과 AegisSentinel의 탐지 모듈 및 대응 액션을 한국어로 정리한 매핑표입니다.

---

## 1. 전술별 커버리지 요약 (11개 전술 · 40개 기법)

| 전술 (한국어 / 영문) | 커버 기법 수 | 대표 기법 ID |
| :--- | :---: | :--- |
| **초기 침투 (Initial Access)** | 2 | `T1091`, `T1195.002` |
| **실행 (Execution)** | 5 | `T1059.001`, `T1059.003`, `T1059.005`, `T1203`, `T1204.002` |
| **지속성 확보 (Persistence)** | 7 | `T1053.005`, `T1546.003`, `T1546.012`, `T1547.001`, `T1547.004`, `T1554`, `T1574.001` |
| **권한 상승 (Privilege Escalation)** | 1 | `T1548.002` |
| **방어 회피 (Defense Evasion)** | 11 | `T1027`, `T1036.003`, `T1036.005`, `T1036.007`, `T1055`, `T1055.012`, `T1127.001`, `T1140`, `T1218.004`, `T1562.001`, `T1562.004` |
| **자격증명 접근 (Credential Access)** | 6 | `T1003.001`, `T1003.002`, `T1003.003`, `T1539`, `T1552.004`, `T1555.003` |
| **내부 정찰 (Discovery)** | 1 | `T1482` |
| **수집 (Collection)** | 1 | `T1115` |
| **명령 및 제어 (Command and Control)** | 2 | `T1071`, `T1090` |
| **데이터 유출 (Exfiltration)** | 1 | `T1041` |
| **영향/파괴 (Impact)** | 3 | `T1486`, `T1490`, `T1565.001` |
| **합계** | **40** | **11개 전술 커버** |

---

## 2. 전체 40개 기법 상세 매핑표

| # | MITRE ID | 전술 | 공격 기법 설명 | 담당 탐지 모듈 | 자동·원클릭 대응 액션 |
| :-: | :--- | :--- | :--- | :--- | :--- |
| 1 | `T1003.001` | 자격증명 접근 | LSASS 메모리 자격증명 덤프 (`comsvcs.dll` 등) | `ProcessRuleEvaluator` + `FilelessScriptGuard` | 프로세스 트리 동결 · 종료 |
| 2 | `T1003.002` | 자격증명 접근 | SAM / SECURITY / SYSTEM 레지스트리 하이브 덤프 | `ProcessRuleEvaluator` | 프로세스 트리 동결 · 종료 |
| 3 | `T1003.003` | 자격증명 접근 | Active Directory `NTDS.dit` 데이터베이스 덤프 | `CustomRuleEngine (AEGIS-004)` | 프로세스 트리 동결 · 종료 |
| 4 | `T1027` | 방어 회피 | 패킹·난독화 파일 및 폴리글랏/스테고/스크립트 은닉 | `PeStaticAnalyzer` + `PolyglotAndMagicSniffer` + `FilelessScriptGuard` + `ScriptFileAnalyzer` | 실행 전 암호화 격리 · 동결 |
| 5 | `T1036.003` | 방어 회피 | 정상 시스템 도구 이름 위장 (리네임드 LOLBin `OriginalFilename`) | `ProcessRuleEvaluator` | 프로세스 트리 동결 · 종료 |
| 6 | `T1036.005` | 방어 회피 | 핵심 Windows 프로세스 경로 사칭 (가짜 `svchost`/`lsass`) | `ProcessRuleEvaluator` | 프로세스 트리 동결 · 격리 |
| 7 | `T1036.007` | 방어 회피 | 문서 위장 이중 확장자 (`.pdf.exe`, `.hwp.lnk`) | `ProcessRuleEvaluator` + `ThreatScanner` + `ZipArchiveAnalyzer` | 실행 전 암호화 격리 · 동결 |
| 8 | `T1041` | 데이터 유출 | C2 채널 유출 (HTTPS 443 / Telegram·Discord 웹훅 / 자격증명 연계) | `NetworkGuardMonitor` + `BehaviorRiskEngine` | 트리 동결 · WFP 방화벽 차단 |
| 9 | `T1053.005` | 지속성 확보 | 악성 예약 작업 (하위 폴더 XML `<Command>` + `<Arguments>` 분석) | `PersistenceMonitor` + `MzkDeepScanner` + `ProcessRuleEvaluator` | `schtasks` 원클릭 삭제 + 연계 파일 격리 |
| 10 | `T1055` | 방어 회피 | 프로세스 메모리 인젝션 (Unbacked Private RWX / 리플렉션) | `MemoryInspectionGuard` + `FilelessScriptGuard` | 프로세스 트리 동결 · 종료 |
| 11 | `T1055.012` | 방어 회피 | 프로세스 할로잉 / 고스팅 (디스크 삭제 후 메모리 실행) | `MemoryInspectionGuard` + `MzkDeepScanner` | 생존 핸들 검증 후 강제 종료 |
| 12 | `T1059.001` | 실행 | PowerShell 악성 실행 (`-EncodedCommand` Base64 디코딩 / 4104) | `ProcessRuleEvaluator` + `FilelessScriptGuard` | 역난독화 탐지 · 즉시 동결 |
| 13 | `T1059.003` | 실행 | Windows 배치 셸 캐럿(`^`) 다형성 난독화 및 드로퍼 | `ScriptFileAnalyzer` + `ProcessRuleEvaluator` | 실행 전 격리 · 동결 |
| 14 | `T1059.005` | 실행 | VBScript / JScript / HTA / WSF / SCT COM 드로퍼 | `ScriptFileAnalyzer` + `ZipArchiveAnalyzer` | 실행 전 암호화 격리 |
| 15 | `T1071` | 명령 및 제어 | 애플리케이션 계층 C2 통신 (실시간 ETW DNS · IPv4/IPv6 · IOC) | `EtwDnsTelemetryService` + `NetworkGuardMonitor` + `ThreatIntelStore` | 연결 직전 동결 · WFP 방화벽 차단 |
| 16 | `T1090` | 명령 및 제어 | 시스템 프록시 / PAC(`AutoConfigURL`) MITM 가로채기 | `EtwKernelTelemetryService` + `SystemIntegrityGuard` + `MzkDeepScanner` | 프록시 원클릭 해제 + WinInet 즉시 갱신 |
| 17 | `T1091` | 초기 침투 | USB 이동식 드라이브(`WM_DEVICECHANGE`) 및 MotW 다운로드 유입 | `DownloadAndUsbGuard` + `ThreatScanner` + `ZipArchiveAnalyzer` | 실시간 자동 스캔 · 즉시 격리 |
| 18 | `T1115` | 수집 | 클립보드 하이재킹 / ClickFix 사회공학 명령 주입 | `ClipboardGuard` (`WM_CLIPBOARDUPDATE` 훅) | 실시간 경고 알림 |
| 19 | `T1127.001` | 방어 회피 | `MSBuild.exe` 인라인 태스크 화이트리스트 우회 실행 | `CustomRuleEngine (AEGIS-002)` | 프로세스 트리 동결 |
| 20 | `T1140` | 방어 회피 | `certutil.exe -decode/-decodehex` 페이로드 복원 | `CustomRuleEngine (AEGIS-001)` | 프로세스 트리 동결 |
| 21 | `T1195.002` | 초기 침투 | 소프트웨어·게임 런처 다단계 공급망 침해 | `ProcessTreeTracker` + `ProcessRuleEvaluator` + `DllSideloadingDetector` | 트리 동결 · 해시 피닝 · DLL 격리 |
| 22 | `T1203` | 실행 | 클라이언트 문서 익스플로잇 (한글 HWP / 오피스 매크로 / PDF) | `ProcessRuleEvaluator` + `SignaturePatternScanner` + `PolyglotAndMagicSniffer` | 프로세스 트리 동결 · 격리 |
| 23 | `T1204.002` | 실행 | 악성 사용자 실행 파일 (짝/홀수 오프셋 `.LNK` / `.ISO` / `.VHD` / `.ZIP` / ADS) | `LnkAndContainerAnalyzer` + `ZipArchiveAnalyzer` + `NtfsAdsScanner` | 메모리 내 검사 · 격리 · ADS 정밀 제거 |
| 24 | `T1218.004` | 방어 회피 | 서명된 시스템 바이너리 프록시 실행 (`InstallUtil`/`RegAsm`/`Mshta`) | `CustomRuleEngine (AEGIS-003)` + `ProcessRuleEvaluator` | 프로세스 트리 동결 |
| 25 | `T1482` | 내부 정찰 | 도메인 트러스트 / AD 정찰 (`nltest` / `adfind`) | `CustomRuleEngine (AEGIS-005)` | 프로세스 트리 동결 |
| 26 | `T1486` | 영향/파괴 | 랜섬웨어 데이터 암호화 (미끼 + 매직헤더 엔트로피 + 변조 속도) | `RansomwareDetector` + `CanaryManager` + `EntropyAnalyzer` + `RecoveryVault` | 즉시 동결 + 복구 금고 1클릭 원본 복원 |
| 27 | `T1490` | 영향/파괴 | 복구 무력화 (`vssadmin`/`wmic shadowcopy`/`wbadmin`/`bcdedit`) | `ProcessRuleEvaluator` + `ScriptFileAnalyzer` + `SignaturePatternScanner` | 즉시 동결 · 종료 |
| 28 | `T1539` | 자격증명 접근 | 브라우저 세션 쿠키 탈취 (Chrome/Edge ABE 원격 디버깅 악용) | `ProcessRuleEvaluator` | 프로세스 트리 동결 |
| 29 | `T1546.003` | 지속성 확보 | WMI 영구 이벤트 소비자(`CommandLineEventConsumer`) 파일리스 지속성 | `PersistenceMonitor` + `MzkDeepScanner` | 실시간 경고 · 전수 감사 |
| 30 | `T1546.012` | 지속성 확보 | IFEO 디버거 실행 가로채기 (`Image File Execution Options`) | `EtwKernelTelemetryService` + `PersistenceMonitor` + `MzkDeepScanner` | 원클릭 레지스트리 롤백 |
| 31 | `T1547.001` | 지속성 확보 | 레지스트리 `Run`/`RunOnce` 및 시작 폴더 자동 실행 | `EtwKernelTelemetryService` + `PersistenceMonitor` + `MzkDeepScanner` | 악성 파일 격리 + 항목 롤백 |
| 32 | `T1547.004` | 지속성 확보 | Winlogon 핵심 키(`Shell` / `Userinit`) 변조 | `EtwKernelTelemetryService` + `PersistenceMonitor` + `MzkDeepScanner` | Windows 안전 기본값 복원 (삭제 방지) |
| 33 | `T1548.002` | 권한 상승 | UAC 우회 (`ms-settings`/`CurVer`/`mscfile`/`fodhelper`) | `EtwKernelTelemetryService` + `SystemIntegrityGuard` + `ProcessRuleEvaluator` | 즉시 자동 롤백 · 동결 |
| 34 | `T1552.004` | 자격증명 접근 | 개인 키 · 클라우드 키(`.ssh`, `.aws`, `.kube`) · 가상자산 지갑 탈취 | `CredentialAndDllGuard` + `EtwKernelTelemetryService` | 트리 동결 · NTFS ACL 권한 잠금 |
| 35 | `T1554` | 지속성 확보 | 승인된 호스트 실행 파일 사후 변조 (SHA-256 해시 핀 불일치) | `ProcessRuleEvaluator` + `SecurityOrchestrator` | 화이트리스트 무시 · 즉시 동결 |
| 36 | `T1555.003` | 자격증명 접근 | 웹 브라우저 비밀번호·쿠키 저장소 탈취 (`Login Data`/`Local State`) | `CredentialAndDllGuard` + `EtwKernelTelemetryService` + `SignaturePatternScanner` | 프로세스 트리 동결 · 격리 |
| 37 | `T1562.001` | 방어 회피 | 보안 도구 무력화 (AMSI 패치 · Defender 경로/확장자/프로세스 예외 · 자가방어 변조) | `FilelessScriptGuard` + `SystemIntegrityGuard` + `PolicyIntegritySigner` + `MzkDeepScanner` | 자가복구 · 예외 원클릭 제거 · 동결 |
| 38 | `T1562.004` | 방어 회피 | Windows 방화벽 비활성화 (`netsh advfirewall`) | `ProcessRuleEvaluator` + `CustomRuleEngine (AEGIS-006)` | 프로세스 트리 동결 |
| 39 | `T1565.001` | 영향/파괴 | Windows `HOSTS` 파일 변조를 통한 보안/금융 DNS 하이재킹 | `SystemIntegrityGuard` + `MzkDeepScanner` + `MalwareRemediationService` | 원본 백업 후 악성 라인만 정밀 제거 |
| 40 | `T1574.001` | 지속성 확보 | DLL 검색 순서 하이재킹 / 공급망 DLL 사이드로딩 (정적+실시간 모듈) | `DllSideloadingDetector` + `CredentialAndDllGuard` + `EtwKernelTelemetryService` | 호스트 종료 · 프록시 DLL 격리 |

---

## 3. MITRE ATT&CK Navigator v4.5 시각화 사용법

1. AegisSentinel 대시보드 우측 상단에서 **`ATT&CK(JSON)`** 버튼을 클릭합니다.
2. 생성된 `AegisSentinel_ATTACK_Layer_YYYYMMDD_HHmmss.json` 파일 경로를 확인합니다.
3. 웹 브라우저에서 [MITRE ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) 접속 → **`Open Existing Layer`** → **`Upload from local`**로 파일을 올립니다.
4. 색상 의미:
   - **에메랄드(`#10b981`, 75점)**: AegisSentinel이 탐지·차단을 지원하는 방어 커버리지 기법
   - **빨간색(`#ef4444`, 100점)**: 현재 PC에서 실제로 탐지·기록된 위협 기법 (관측 횟수 및 담당 모듈 주석 자동 포함)
