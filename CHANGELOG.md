# 변경 이력 (Changelog)

이 프로젝트의 모든 주요 변경 사항은 이 문서에 기록합니다.  
형식은 [Keep a Changelog 1.1.0](https://keepachangelog.com/ko/1.1.0/)을 따르며, 버전 번호는 [Semantic Versioning 2.0.0](https://semver.org/lang/ko/)을 준수합니다.

---

## [Unreleased]

---

## [1.2.0] - 2026-11-27

### 추가 (Added)
- **청크 인증 스트리밍 암호화 포맷 `AEGISQ3` (`QuarantineManager`)**: 64 MiB 초과 대용량 파일 및 격리 도중 크기가 증가한 파일에 고정 키 XOR(`AEGISQ1`) 대신 청크 단위 **AES-256-GCM AEAD**(`AEGISQ3\0` 헤더, 12바이트 랜덤 기본 Nonce ⊕ 64비트 청크 인덱스, AAD에 매직·청크 인덱스·최종 청크 플래그·평문 길이 바인딩)를 적용해 청크 변조·재배치·절단·후미 확장을 암호학적으로 차단.
- **격리 아티팩트 실제 암호화 형식 기록 (`QuarantineEntry.EncryptionFormat`)**: 메타데이터와 `SecurityOrchestrator` 감사 로그(`ContainmentDetail`)에 실제 사용된 암호화 형식(`AES-256-GCM` vs `AES-256-GCM-Chunked`)을 정확히 기록.
- **재현 가능한 정량 벤치마크 스위트 및 문서 (`RansomwareDefenseBenchmarkTests` · `docs/BENCHMARKS.md`)**: 문서 피해 최소화·100% SHA-256 복구(`0/50` 변조, `20 ms`, `50/50` 복구), 정상 작업 1,000회 오동결 `0건`(`155.02 µs/op`), 6대 장애 주입 무손실(`6/6`) 벤치마크 추가.

### 수정 (Fixed)
- **격리 중 파일 크기 증가 경계 돌파 복원 불가 결함 수정 (`P1`)**: `QuarantineFile()`이 단일 AES-GCM(`AEGISQ2`) 읽기 상한(`effectiveInMemoryLimit + 1`)을 초과하는 즉시 버퍼링된 바이트와 남은 스트림을 끊김 없이 `AEGISQ3` 청크 AES-256-GCM으로 자동 전환(Spill)하며, 원본 삭제 전 `IsQuarantineArtifactRestorable()`로 복원 가능 형식을 검증.
- **레거시 `AEGISQ1` 하위 호환 복원 유지**: 기존에 격리된 `AEGISQ1\0` 파일은 복원 경로에서 계속 안전하게 임시 파일 검증·원자적 복원 지원.

### 테스트 (Tests)
- `QuarantineChunkedAeadRegressionTests` 3종(대용량 `AEGISQ3`·감사 형식, 격리 중 크기 증가 자동 전환·원본 바이트 100% 복원, 1비트 변조/절단/후미 확장 거부 및 0바이트·정확한 청크 경계 검증) + `RansomwareDefenseBenchmarkTests` 3종 추가 (전체 **62 / 62 통과**).

---

## [1.1.2] - 2026-11-26

### 수정 (Fixed)
- **동결 유지 vs 종료 재시도 상태 분리 (`SecurityModels` · `SecurityOrchestrator`)**: `KillAndQuarantineResult`에서 `RemainingSuspendedChildPids`(`StillSuspendedByUs == true`만 포함)와 `RetryRequiredChildPids`(`TransientFailureRetryRequired` 포함)를 분리하고, `SecurityEvent.PendingTerminationRetryChildPids`를 신설. 한 번도 동결되지 않은 자식의 종료 핸들 열기가 실패해도 동결 목록이나 `_activeInterventionPids`에 잘못 들어가지 않아 후속 악성 이벤트가 정상적으로 계속 처리됨.
- **부모 신원 사전 확인 3분류 (`ProcessController` · `SecurityOrchestrator`)**: `VerifyProcessInstanceIdentity()` 및 `TryInspectProcessInstanceIdentity()`가 `Matched` / `ExitedOrReplaced` / `LookupFailed`를 구분. 일시적 조회·권한 오류(`LookupFailed`) 시 부모·자손 종료를 보류하고 기존 동결 추적 상태를 유지해 다음 재시도에서 안전하게 처리.
- **엄격 모드(Strict) 자동 종료 실패 시 사용자 경고 인계 (`SecurityOrchestrator`)**: 엄격 모드 자동 대응이 `KillAndQuarantineDetailed()` 결과를 확인해 실제 동결 대상이 남으면 `UserInterventionRequired`를 발생시켜 사용자가 종료를 재시도하거나 재개할 수 있도록 수정.

### 테스트 (Tests)
- `ContainmentFailurePathRegressionTests` 3종 추가 (엄격 모드 자식 종료 실패 → 사용자 개입 이벤트 1회 발생, 미동결 자식 종료 핸들 실패 → 재시도 목록 분리 및 후속 이벤트 처리, 부모 신원·경로 조회 실패 → 보류 및 재시도 성공 — 전체 **56 / 56 통과**).

---

## [1.1.1] - 2026-11-26

### 수정 (Fixed)
- **재부팅 삭제 예약 취소 실패 시 격리 사본 보존 (`QuarantineManager`)**: `TryCancelPendingRebootDelete()`가 레지스트리 변경 및 재조회 확인 결과를 `bool`로 반환하도록 변경. 취소 확인 실패 시 `QuarantineRestoreStatus.RestoredButRebootDeleteCancelFailed`를 반환하고 격리 사본(`.aegisq`·`.json`)을 삭제하지 않고 보존.
- **‘종료 및 격리’ 자식 종료 실패 추적 유지 및 경고창 재시도 (`SecurityOrchestrator` · `ThreatPromptWindow` · `MainWindow`)**: `TryTerminateProcessInstanceDetailed()`·`KillAndQuarantineDetailed()`가 프로세스별 종료 결과를 반환하고, 종료에 실패한 동결 자식/부모는 추적 목록에 유지하며 경고창을 닫지 않고 재시도 또는 재개할 수 있도록 수정.
- **프로세스 생성 시각 조회 실패 3분류 (`ProcessController`)**: `VerifyHandleCreationTime()`이 `Matched` / `Mismatched` / `LookupFailed`를 명확히 구분해 조회 실패 시 재개(`ResumeProcess`)·종료(`TerminateProcess`)와 `_suspendedPids` 추적 삭제를 모두 보류(`TransientFailureRetryRequired`).
- **경고 대기열 포화 시 자동 재개 실패 사건 인계 (`ThreatPromptQueueCoordinator` · `App.xaml.cs`)**: 해제 콜백이 완료 여부(`bool`)를 반환하도록 변경하고, 실패한 사건은 `_unresolvedRetryEvents`에 보존해 활성 경고 종료 시 최우선으로 사용자에게 표시 및 `RetryUnresolvedReleases()` 재시도를 지원.

### 테스트 (Tests)
- `ContainmentFailurePathRegressionTests` 4종 추가 (재부팅 삭제 예약 취소 실패, 자식 종료 실패 + WPF 경고창 유지, 생성 시각 조회 실패 후 재시도, 대기열 포화 자식 재개 실패 인계 — 전체 **53 / 53 통과**).

---

## [1.1.0] - 2026-11-26

### 추가 (Added)
- **단일 핸들 프로세스 신원 검증 (`IProcessNativeOperations` · `ProcessInstanceIdentity`)**: 동결 시점에 단일 핸들(`GetProcessTimes`)에서 프로세스 생성 시각(`CreationTimeFileTimeUtc`)과 실행 경로를 확보하고, 종료 시 동일 핸들에서 신원 검증 직후 `TerminateProcess`를 실행해 PID 재사용 오종료를 차단 (`P1-1`).
- **경고 대기열 코디네이터 (`ThreatPromptQueueCoordinator`)**: `SecurityEvent.HasAnySuspendedProcess` 공통 판정 기반으로 대기열 포화·중복 병합·앱 종료 경로를 일원화해 자식만 동결된 사건이 유실되거나 기존 경고 소유 프로세스가 조기 해제되지 않도록 보호 (`P1-2`).
- **감사 로그 스키마 버전 (`SchemaVersion = 2`)**: 신규 감사 로그 기록 시 스키마 버전을 명시하고 구버전 로그와의 하위 호환성을 유지 (`P2-1`).
- **NTFS 디렉터리 메타데이터 플러시 (`TryFlushDirectoryMetadata`)**: 격리 메타데이터 및 복원 커밋 직후 상위 디렉터리에 `FlushFileBuffers`를 호출해 전원 차단 내구성 보강.
- **회귀·실환경 자동 검증 10종 (`ContainmentSafetyRegressionTests`)**: `P1-1~P1-5`·`P2-1` 회귀 테스트 6종과 실제 Win32 실프로세스(`ping.exe`), 실제 OS 배타적 파일 잠금(`FileShare.None`), 대용량 스트리밍(`AEGISQ1`), 실제 WPF STA 창 클릭 검증 4종 추가 (전체 **49 / 49 통과**).
- **오픈소스 저장소 표준 거버넌스**: `SECURITY.md`, `CONTRIBUTING.md`, `CHANGELOG.md`, `.editorconfig`, `.gitattributes`, `.github/CODEOWNERS`, PR 템플릿, YAML 이슈 폼(버그·오탐 제보 / 기능 제안) 도입.

### 변경 · 수정 (Changed / Fixed)
- **부분 재개 추적 유지 및 재시도 UI (`P1-3`)**: `TryResumeProcessDetailed()`가 OS 호출 전에 `_suspendedPids`를 지우지 않고 `Resumed` / `AlreadyExitedOrReplaced` / `TransientFailureRetryRequired`로 분류. 실패 대상만 추적 목록에 유지하고 `SecurityActionTaken.PartiallyAllowed`를 감사 로그와 `ThreatPromptWindow`·`MainWindow`에 표시하며 재시도를 지원.
- **격리 메타데이터 선저장 및 중단 복구 (`P1-4`)**: `QuarantineFile()`이 암호화 격리 사본(`Flush(true)`)과 `PendingOriginalRemoval` 메타데이터 JSON을 원본 삭제·재부팅 예약 이전에 디스크에 커밋. 중단 후 재시작 시 `ListEntries()`가 실제 파일 존재 여부와 HKLM `PendingFileRenameOperations`를 대조해 자동 복구.
- **원자적 격리 복원 및 대상 충돌 보호 (`P1-5`)**: `AEGISQ2`(AES-256-GCM)와 `AEGISQ1`(대용량 스트리밍) 복원 모두 대상 디렉터리 임시 파일에 복호화·`Flush(true)`·디스크 SHA-256 재검증 후 원자적 교체. 기존 파일 존재 시 기본 `DestinationConflict`를 반환하고 `MainWindow` 확인 대화상자 승인 시에만 덮어쓰기 수행.
- **`SecurityActionTaken` Enum 번호 복원 (`P2-1`)**: 기존 감사 로그 호환성을 위해 `FirewallBlocked=4`, `RolledBack=5`, `Allowed=6`을 원래 번호로 복원하고 신규 값을 `7~9`에 배치.

---

## [1.0.1] - 2026-11-26

### 수정 (Fixed)
- **격리 결과 구조화 (`QuarantineDisposition`)**: `RemovedImmediately`, `ScheduledDeleteOnReboot`, `CopyOnlyOriginalLocked`를 구분해 원본 미제거 시 `Quarantined`로 과대 기록하지 않도록 수정.
- **부분 트리 동결 정확도 개선**: `TrySuspendProcessTreeDetailed()`가 부모 동결 여부와 실제 동결된 자식 PID 목록만 반환·추적하도록 수정.
- **행위 위험 점수 일관성 개선**: `BehaviorRiskEngine`의 자격증명 접근 + 외부 통신 연계 보너스(+45점)를 원본 신호 만료 시각에 맞춰 평가 시 동적 계산하도록 변경.
- **원자적 이벤트 중복 제거**: `SecurityOrchestrator`의 동시 이벤트 중복 제거를 원자적 연산으로 개선.

---

## [1.0.0] - 2026-11-25

### 추가 (Added)
- **9계층 실시간 EDR 방어 엔진**: 커널 ETW(`NT Kernel Logger` + `DNS-Client`), 랜섬웨어 4중 방어(미끼·엔트로피·속도·복구 금고), 공급망·자격증명·지속성·네트워크·파일리스·메모리 인젝션·클립보드·USB 가드.
- **MZK급 6단계 정밀 백신 및 상용 백신 초월 4대 심층 엔진**: O(1) 메모리 무제한 스트리밍 BFS 스캐너, 폴리글랏/스테고/원시 셸코드 스니퍼, DLL 사이드로딩 감지기, NTFS ADS 스캐너, 탈취 인증서 YARA 검사, 원클릭 비파괴 치료.
- **암호화 격리소 및 자가방어**: AES-256-GCM 격리소, DPAPI+HMAC+레지스트리 Witness 정책 무결성 보호, WFP 커널 방화벽 연동, WPF 다크모드 통합 대시보드 및 문서(`README.md`, `docs/*`).

---

[Unreleased]: https://github.com/kjm0719/AegisSentinel/compare/v1.2.0...HEAD
[1.2.0]: https://github.com/kjm0719/AegisSentinel/compare/v1.1.2...v1.2.0
[1.1.2]: https://github.com/kjm0719/AegisSentinel/compare/v1.1.1...v1.1.2
[1.1.1]: https://github.com/kjm0719/AegisSentinel/compare/v1.1.0...v1.1.1
[1.1.0]: https://github.com/kjm0719/AegisSentinel/compare/v1.0.1...v1.1.0
[1.0.1]: https://github.com/kjm0719/AegisSentinel/compare/v1.0.0...v1.0.1
[1.0.0]: https://github.com/kjm0719/AegisSentinel/releases/tag/v1.0.0
