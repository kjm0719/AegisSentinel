# AegisSentinel 심층 기술 해설 & 면접 대비 Q&A 12선

> 보안 솔루션 개발 · EDR/백신 탐지 엔지니어링 · 침해대응(CERT/SOC) 관점에서 자주 나오는 핵심 질문과, **AegisSentinel 실제 구현 코드 및 실전 트러블슈팅 경험**에 근거한 답변을 한국어로 정리했습니다.

---

### Q1. 유저모드(Ring-3) EDR인데 커널 드라이버(Ring-0) 없이 어디까지 막을 수 있고, 한계는 어떻게 보완했나요?
- **핵심 답변**:
  - 유저모드(Ring-3) 단독으로는 BYOVD 커널 루트킷, 미니필터 수준의 동기 파일 I/O 차단(`IRP_MJ_CREATE`), 그리고 SYSTEM 권한 탈취 시 프로세스 강제 종료(PPL 부재)를 완전히 막을 수 없다는 점을 명확히 인지하고 있습니다.
  - 이를 보완하기 위해 첫째, 대상 프로세스에 DLL을 인젝션해 API를 후킹하는 대신 **커널이 직접 발행하는 `NT Kernel Logger` ETW 스트림**을 구독해 악성코드의 `ntdll` 언후킹이나 Direct Syscall 우회를 무력화했습니다.
  - 둘째, 커널 동기 차단이 필요한 영역은 OS 내장 커널 보안(**Windows Defender CFA · 5대 ASR 규칙 · HVCI**)과 `WindowsSecurityHardening`으로 결합해 심층 방어를 구성했습니다.

---

### Q2. 기존 상용 백신도 놓쳤던 니케(NIKKE)형 공급망 공격이나 은닉 악성코드는 어떻게 잡아내나요?
- **핵심 답변**:
  - 상용 백신이 놓치는 대표 원인은 ① 정상 서명된 호스트 실행파일을 과신하고 옆에 놓인 미서명 프록시 DLL을 방치하거나, ② `.png`/`.pdf`/`.dat` 같은 비실행 확장자를 스캔에서 제외하거나, ③ 탐색기에 안 보이는 NTFS 숨김 스트림(ADS)이나 탈취된 서드파티 인증서 바이너리를 건너뛰기 때문입니다.
  - AegisSentinel은 이를 막기 위해 **4대 심층 탐지 엔진**을 직접 구축했습니다:
    1. `DllSideloadingDetector`: 서명된 `.exe` 옆의 미서명 시스템명 DLL(`version.dll`, `winmm.dll`, `dbghelp.dll` 등)을 **디스크 정적 검사 + 실행 중 프로세스 모듈 검사** 이중으로 포착.
    2. `PolyglotAndMagicSniffer`: 확장자를 무시하고 헤더(4 KB)·테일(256 KB)을 검사해 `.png`/`.jpg`/`.pdf`/`.dat` 내부의 위장 PE, `IEND`/`EOI` 뒤 폴리글랏 페이로드, 원시 PEB 워킹 셸코드를 탐지.
    3. `NtfsAdsScanner`: `FindFirstStreamW`로 `notes.txt:dropper.exe` 숨김 스트림을 탐지하고 원본 파일은 유지한 채 스트림만 정밀 제거.
    4. `SignaturePatternScanner`: `TrustedMicrosoft`만 면제하고 서드파티 서명 바이너리도 고신뢰 YARA 규칙으로 검사.

---

### Q3. 파일 수 제한 없이 깊이 100% 전체를 검사하면 메모리가 터지지 않나요?
- **핵심 답변**:
  - 전체 파일 경로를 리스트에 먼저 모은 뒤 스캔하면 수십만~수백만 파일이 쌓여 RAM이 폭주할 수 있습니다.
  - `MzkDeepScanner`는 용량이 **2,048개로 고정된 `BlockingCollection<string>`** 기반의 **생산자-소비자 스트리밍 BFS 파이프라인**으로 설계했습니다.
  - 단일 생산자가 너비우선탐색(최대 깊이 64, 파일 수 무제한)으로 경로를 밀어 넣고 2~4개 소비자가 병렬로 검사한 뒤 즉시 해제합니다. 대기열이 2,048개에 도달하면 생산자가 자동으로 대기(Backpressure)하므로 디스크가 아무리 커도 대기열 RAM은 약 0.5 MB 수준으로 일정하게 유지됩니다.

---

### Q4. 실제 개발 환경(본인 PC)에서 겪은 치명적 오탐 사례와 포렌식 해결 과정을 설명해 주세요.
- **핵심 답변**:
  - 실제 PC의 로그(`events-*.jsonl`)와 `intel.json`을 직접 포렌식 분석하면서 실전급 오탐 4건을 찾아 근본 해결했습니다:
    1. **공용 CDN/클라우드 IP 피드 오염**: 공개 IPsum 피드에 Cloudflare(`104.28.*`), Microsoft Azure/FrontDoor(`13.107.*`, `20.*`, `40.*`, `52.*`), Akamai(`23.*`) IP가 섞여 들어와 VS Code·Phone Link가 443 HTTPS 연결에서 동결되던 문제를 발견 → `IsProtectedInfrastructureOrCdnIp` 대역 필터를 동기화와 로드 시점에 모두 적용해 자동 정화.
    2. **광고 목록(StevenBlack) vs 확정 C2 도메인 혼재**: Microsoft 실험 텔레메트리(`default.exp-tas.com`)가 광고 목록에 들어 있어 `PhoneExperienceHost.exe`와 `Dnscache`(`svchost.exe`, Event 3020)에 연쇄 경보가 뜬 문제 → 실시간 ETW DNS는 확정 C2(사용자 IOC + URLhaus)만 사용하고, Event 3020 및 `WindowsApps\Microsoft.*` 핵심 OS 프로세스 보호 강화.
    3. **개발자 CLI 플래그 충돌 (`rg -e`, `docker -e`)**: PowerShell `-EncodedCommand` 축약 플래그 정규식을 PowerShell 계열 프로세스 전용으로 격리.
    4. **암호 보호된 Office 문서 오탐**: 암호를 건 `.docx`/`.xlsx`/`.hwpx`는 ZIP(`50 4B 03 04`) 대신 OLE2(`D0 CF 11 E0`) 헤더에 고엔트로피 본문을 가지므로 `EntropyAnalyzer`에서 OLE2 헤더를 정상 허용.

---

### Q5. Windows 시스템 파일 서명 검증에서 단순 `WinVerifyTrust`만으로 부족한 이유는 무엇인가요?
- **핵심 답변**:
  - `explorer.exe`, `notepad.exe` 등 수많은 Windows 기본 실행파일은 바이너리 자체에 Authenticode 서명을 내장하지 않고, 시스템 카탈로그(`.cat`)에 해시를 등록해 서명합니다.
  - 단순 `WinVerifyTrust(WTD_CHOICE_FILE)`만 호출하면 `TRUST_E_NOSIGNATURE`가 반환되는데, 이때 `C:\Windows\System32\` 경로만 보고 `TrustedMicrosoft`로 간주하면 경로 기반 신뢰 구멍이 생깁니다.
  - 그래서 `SignatureVerifier`에 `CryptCATAdminAcquireContext2` → `CryptCATAdminCalcHashFromFileHandle2` → `CryptCATAdminEnumCatalogFromHash` → `WinVerifyTrust(WTD_CHOICE_CATALOG)` 파이프라인을 직접 P/Invoke 구현해 진짜 암호학적 카탈로그 서명을 검증합니다.

---

### Q6. ETW는 비동기(Asynchronous)인데 랜섬웨어가 암호화를 먼저 시작하면 어떻게 대응하나요?
- **핵심 답변**:
  - 4중 방어선으로 비동기 지연 피해를 최소화합니다:
    1. 사전 준비 단계(`vssadmin`/`wbadmin`/`bcdedit`, `T1490`)에서 `NtSuspendProcess`로 프로세스 **전체 트리**를 즉시 동결.
    2. 보호 폴더 상단에 미끼(Canary) 파일을 배치해 암호화가 시작되자마자 첫 변조에 즉시 트리거.
    3. `EntropyAnalyzer`가 매직 헤더 손상 + 섀넌 엔트로피를 결합해 저속 암호화(Slow Encryption)도 탐지.
    4. 초기 일부 파일이 암호화되더라도 `RecoveryVault`의 SHA-256 검증 스냅샷으로 1클릭 복원하며, 근본 사전 차단은 Defender CFA 커널 보호와 연동.

---

### Q7. 성능 최적화와 배터리 절약을 위해 어떤 수치 측정과 튜닝을 했나요?
- **핵심 답변**:
  - 마이크로 벤치마크(`EnginePerformance_MicroBenchmarks_ReportEmpiricalLatency`)로 병목을 계측해 `ProcessRuleEvaluator`의 `FileVersionInfo` 반복 디스크 I/O 병목(`251.04 µs/op`)을 포착했고, `(LastWriteTimeUtc.Ticks, Length)` 검증 512엔트리 캐시를 도입해 **`38.98 µs/op`(6.4배 단축)**으로 개선했습니다.
  - 악성 해시 DB는 10만+ 건의 64자 문자열 대신 정렬된 32바이트 바이너리 이진 탐색(`O(log N)`)으로 **약 0.73 µs/op**, 도메인 조회는 `O(라벨수)` 해시셋 조회로 **0.92 µs/op**를 달성했습니다.
  - 클립보드(`WM_CLIPBOARDUPDATE`)와 USB(`WM_DEVICECHANGE`)는 폴링 대신 Win32 이벤트 훅을 사용하고, 노트북 배터리 전환 시 보조 타이머 주기를 자동 2배 완화합니다.

---

### Q8. 공격자가 설정 파일(`policy.json`)이나 서명(`.hmac`) 파일을 지우면 어떻게 막나요?
- **핵심 답변**:
  - `PolicyIntegritySigner`가 기기 종속 Windows DPAPI 키로 HMAC-SHA256 서명을 생성하며, `policy.json`, `rules.json`, `pup_rules.json`, `RecoveryVault` 인덱스를 모두 보호합니다.
  - 특히 코드리뷰에서 "공격자가 `.hmac`과 `.aegis_seal.key`를 동시에 삭제해 초기 마이그레이션으로 위장하는 우회"를 발견해 `HKCU\Software\AegisSentinel\IntegrityWitness` 레지스트리 Witness를 추가했습니다. 파일이 지워져도 Witness가 존재하면 즉시 변조(`T1562.001`)로 감지해 안전 기본값으로 자동 복구합니다.

---

### Q9. Detection-as-Code 커스텀 룰 엔진(`CustomRuleEngine`)의 ReDoS와 동시성 설계는?
- **핵심 답변**:
  - .NET 10의 `RegexOptions.NonBacktracking`(선형 시간 $O(n)$ 보장)으로 컴파일하고 중첩 수량자(`(a+)+`)를 사전 거부하며 200ms 타임아웃을 강제합니다.
  - 핫 ETW 읽기 경로의 스레드 경합을 없애기 위해 `volatile IReadOnlyList<CompiledRule>`을 사용해 룰 수정 시 백그라운드에서 새 목록을 컴파일한 뒤 참조만 원자적으로 교체(Lock-Free Snapshot Swap)합니다.

---

### Q10. 백신/EDR 오탐으로 사용자 문서나 Windows를 망가뜨리지 않기 위한 안전 설계는?
- **핵심 답변**:
  - 1) `QuarantineManager.IsProtectedSystemOrSelfPath`와 `ProcessController.IsCriticalProtectedProcess`를 격리·종료·방화벽 차단 전체에 공유 적용해 `svchost`, `explorer`, `WindowsApps\Microsoft.*`, Defender, 자사 폴더를 절대 건드리지 않습니다.
  - 2) 악성 파일은 영구 삭제 대신 **AES-256-GCM 인증 암호화 격리소**로 이동해 언제든 복원 가능하며, 변조된 브라우저 `.lnk`는 아이콘을 보존한 채 인자만 제거하고, NTFS ADS는 호스트 문서를 보존한 채 스트림만 제거합니다.
  - 3) 이 안전 가드레일들은 38개 xUnit 자동화 테스트로 매 빌드마다 회귀 검증합니다.

---

### Q11. 경고 팝업이 여러 개 겹치거나 작업 중 포커스를 빼앗기는 UX 문제는 어떻게 해결했나요?
- **핵심 답변**:
  - 기존 다중 팝업 구조에서는 5번째 이후 동결 프로세스가 팝업 상한에 걸려 영원히 얼어붙거나, 화면 중앙에 포커스를 강탈해 타이핑 중 실수로 허용 버튼이 눌리는 문제가 있었습니다.
  - 이를 **단일 활성 팝업 + FIFO 대기열(`+N건 대기 중`)**로 개편하고, 화면 우측 하단에 `ShowActivated="False"`로 띄워 포커스를 뺏지 않도록 했습니다. 또한 X 버튼으로 닫을 때는 30분 세션 면제를 주지 않고 동결만 안전하게 해제하며, 앱 종료 시 대기열의 모든 동결 프로세스도 빠짐없이 해제합니다.

---

### Q12. 이 프로젝트를 수천 대 규모 기업용 EDR로 확장한다면 어떤 구조를 추가하겠나요?
- **핵심 답변**:
  - 현재 탐지/대응 코어(`AegisSentinel.Core`)와 UI(`AegisSentinel.App`)가 깔끔히 분리되어 있고, 로그와 커버리지가 JSONL + MITRE ATT&CK v4.5 표준 포맷입니다.
  - 기업 확장 시 ① UI와 분리된 Windows Service(SYSTEM/PPL) 데몬화, ② gRPC/mTLS 기반 중앙 관리 서버로 JSONL 이벤트·`TelemetrySnapshot` 배치 스트리밍(SIEM 연동), ③ 중앙 서명된 `rules.json` 및 IOC 피드 원격 롤아웃, ④ WHQL 서명 커널 미니필터(`FltRegisterFilter`/`ObRegisterCallbacks`) 도입으로 Ring-0 동기 차단까지 완성할 수 있습니다.
