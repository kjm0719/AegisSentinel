# AegisSentinel 변경 이력 (CHANGELOG)

모든 주요 기능 추가, 보안 강화, 버그 수정 및 테스트 검증 내역을 시간 역순으로 기록합니다.

---

## [2026-11-26] P1-1~P1-5 · P2-1 격리/프로세스 제어 안전성 강화 및 실환경 검증 보강

### 보안 · 안정성 수정
- **P1-1 (PID 재사용 오종료 차단)**: 동결 시점에 단일 핸들(`GetProcessTimes`)로 프로세스 생성 시각(`CreationTimeFileTimeUtc`)과 실행 경로를 기록하고, `TryTerminateProcessInstance()`가 `PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION` 단일 핸들에서 신원 검증 직후 `TerminateProcess`를 수행하도록 변경 (TOCTOU 제거).
- **P1-2 (자식만 동결된 경고 유실 방지)**: `SecurityEvent.HasAnySuspendedProcess` 공통 판정과 `ThreatPromptQueueCoordinator`를 도입해 경고 대기열 포화·중복 병합·앱 종료 시 자식 프로세스만 동결된 사건이 방치되거나 기존 경고가 관리 중인 프로세스가 조기 해제되지 않도록 개선.
- **P1-3 (재개 실패 시 추적 유지 및 부분 성공 보고)**: `TryResumeProcessDetailed()`가 `Resumed` / `AlreadyExitedOrReplaced` / `TransientFailureRetryRequired`를 구분하고 일시 실패 대상은 `_suspendedPids`와 이벤트 추적 목록에 유지. 부분 재개 시 `SecurityActionTaken.PartiallyAllowed`를 감사 로그와 UI(`ThreatPromptWindow`, `MainWindow`)에 표시하고 재시도 가능하도록 개선.
- **P1-4 (복원 메타데이터 선저장 및 중단 복구)**: `QuarantineFile()`이 암호화 격리 사본(`Flush(true)`)과 `PendingOriginalRemoval` 메타데이터 JSON(원자적 교체 + `FlushFileBuffers` 디렉터리 플러시)을 원본 삭제·재부팅 예약 이전에 커밋하도록 변경. 중단 후 재시작 시 `ListEntries()`가 실제 파일 존재 여부와 HKLM `PendingFileRenameOperations`를 대조해 자동 복구.
- **P1-5 (복원 충돌 보호 및 원자적 교체)**: AES-256-GCM(`AEGISQ2`) 및 대용량 스트리밍(`AEGISQ1`) 복원 경로 모두 대상 디렉터리 임시 파일에 복호화·`Flush(true)`·디스크 SHA-256 재검증 후 원자적 교체(`File.Move`/`File.Replace` + 디렉터리 플러시). 기존 파일 존재 시 기본 `DestinationConflict` 반환 후 UI 확인(`MainWindow`) 시에만 명시적 덮어쓰기 허용.
- **P2-1 (감사 로그 Enum 하위 호환성 및 스키마 버전)**: `SecurityActionTaken` 기존 번호 `0~6`(`FirewallBlocked=4`, `RolledBack=5`, `Allowed=6`)을 복원하고 신규 값을 `7~9`에 배치. 신규 감사 로그에 `SchemaVersion = 2`를 기록하며 구버전 로그는 임의 치환 없이 그대로 역직렬화.

### 검증 결과
- Release 클린 빌드 (`-warnaserror`): 경고 0건, 오류 0건
- 전체 자동 테스트: **49 / 49 통과** (신규 회귀 6건 + 실제 Win32 실프로세스·OS 배타적 파일 잠금·`AEGISQ1` 스트리밍·WPF STA UI 검증 4건 포함)
- Windows Defender 빌드 산출물 스캔: 위협 없음 (`DEFENDER_EXIT=0`)

---

## [2026-11-26] `acbc7de` — 격리 상태·부분 동결·유출 보너스 만료·원자적 중복 제거 로직 개선

### 수정 사항
- **격리 결과 구조화 (`QuarantineDisposition`)**: `RemovedImmediately`, `ScheduledDeleteOnReboot`, `CopyOnlyOriginalLocked`를 구분해 원본 미제거 시 `Quarantined`로 과대 기록하지 않도록 수정.
- **부분 트리 동결 정확도 개선**: `TrySuspendProcessTreeDetailed()`가 부모 성공 여부와 실제 동결된 자식 PID 목록만 반환·추적하도록 수정.
- **행위 위험 점수 일관성 개선**: `BehaviorRiskEngine`의 자격증명 접근 + 외부 통신 연계 보너스(+45점)를 원본 신호 만료 시각에 맞춰 평가 시 동적 계산하도록 변경.
- **원자적 이벤트 중복 제거**: `SecurityOrchestrator`의 동시 이벤트 중복 제거를 원자적 연산으로 개선.

---

## [2026-11-25] `0cdd8c3` — 초기 커밋: AegisSentinel Windows 통합 EDR 및 MZK 6단계 심층 백신

### 초기 구성
- Windows 실시간 9중 EDR 방어 엔진(ETW 커널·DNS 텔레메트리, 랜섬웨어 카나리/엔트로피 탐지, 복구 금고, 공급망·자격증명·지속성·네트워크·파일리스·메모리 인젝션 가드)
- MZK급 6단계 정밀 바이러스 검사 및 일괄 치료 엔진(대용량 해시 DB, YARA-X 스타일 시그니처, PE/스크립트/ZIP/LNK/ADS/폴리글롯 분석, Defender 교차 검증)
- AES-256-GCM 격리소, DPAPI-HMAC 정책 무결성 보호, WFP 방화벽 연동, WPF 커맨드 센터 UI 및 문서화(`README.md`, `docs/*`)
