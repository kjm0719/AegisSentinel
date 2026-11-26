# AegisSentinel 정량 평가 및 재현 가능 벤치마크 (Benchmarks)

이 문서는 **“AegisSentinel을 추가했을 때 실제 사용자 문서 피해가 얼마나 줄었는가, 정상 작업 비용은 얼마인가, 장애 시에도 사용자 데이터가 남는가”**라는 세 가지 핵심 질문에 재현 가능한 수치로 답하기 위한 평가 프로토콜과 실측 결과를 기록합니다.

---

## 1. 재현 방법 (누구나 동일 조건으로 실행 가능)

모든 자동화 벤치마크는 격리된 `%TEMP%\AegisBench_*` 디렉터리에서만 실행되며 사용자의 실제 파일이나 시스템 설정을 건드리지 않습니다.

```powershell
# 1. 클린 Release 빌드 (-warnaserror)
dotnet build AegisSentinel.slnx -c Release --no-incremental -warnaserror

# 2. 정량 벤치마크 4종 실행 (실측 수치 출력)
dotnet test tests/AegisSentinel.Tests/AegisSentinel.Tests.csproj -c Release --no-build --filter "FullyQualifiedName~RansomwareDefenseBenchmarkTests" --logger "console;verbosity=detailed"
```

---

## 2. 자동화 벤치마크 실측 결과 (Windows 11 x64 · .NET 10 Release)

### 2.1 실제 별도 OS 프로세스 보호 전·후 A/B 비교 (`Benchmark_01B` — 핵심 실측)
- **조건**: 별도의 `powershell.exe` 자식 프로세스가 격리된 임시 문서 20개(`doc_00.txt` ~ `doc_19.txt`)만 **동일한 순서**로 덮어씀 (**미끼 파일 선탐지 비활성화** — 순수 행위 탐지 + 실제 `FileSystemWatcher` + Win32 Restart Manager PID 귀속 + 실제 Win32 `NtSuspendProcess` 동결 + `RecoveryVault` 복구).

| 측정 항목 | 보호 전 (AegisSentinel OFF) | 보호 후 (AegisSentinel ON) |
| :--- | :---: | :---: |
| **실제 변조된 문서 수 (SHA-256 기준)** | **`20 / 20`** (`4,357 ms` 완료) | **`3 / 20`** (`1,059 ms`에 실제 OS 동결) |
| **동결 전 무손상 보존 문서 수** | `0 / 20` | **`17 / 20`** (피해 85% 차단) |
| **복구 후 원본 SHA-256 일치 문서 수** | `0 / 20` | **`20 / 20 (100%)`** |

### 2.2 단위 규칙 반응 · 정상 작업 비용 · 장애 내구성 기준선

| 평가 항목 | 벤치마크 테스트 | 측정 범위 및 조건 | 실측 결과 |
| :--- | :--- | :--- | :---: |
| **미끼 우선 탐지 규칙 반응** *(단위 기준선)* | `Benchmark_01A_CanaryFirstRuleReaction_UnitBaseline` | 알파벳순 미끼 우선 시나리오에서 `RansomwareDetector` 규칙 직접 호출 반응 *(실제 OS 동결 미포함)* | 규칙 반응 전 변조 **`0 / 50`**, 규칙 반응 **`15 ms`** |
| **정상 작업 비용 & 오동결** | `Benchmark_02_NormalWorkflowOverhead` | 개발·브라우저/게임·스크립트·대량 복사 합성 정상 작업 1,000회 | 오동결 **`0 / 1,000`**, 오탐 **`0 / 1,000`**, 평균 **`246.10 µs/op`** (`246 ms`) |
| **장애 시 사용자 데이터 보존** | `Benchmark_03_FaultResilienceMatrix` | 7대 주입 장애(디스크 부족·삭제 직후 중단·실제 OS 배타적 잠금·복원 충돌·재부팅 삭제 취소 실패·경계 초과 크기 증가·사본 저장 직후 원본 교체 TOCTOU) | **`7 / 7 (100% 무손실)`** |

---

## 3. 실환경 장기 비교 평가 프로토콜 (다음 이정표)

위 결과는 누구나 수 초 내에 재현할 수 있는 자동화 기준선이며, 장기 실환경 및 상용 제품 대비 비교는 다음과 같이 분리해 관리합니다.

| 비교 항목 | 대조군 (Baseline) | 실험군 (Treatment) | 공개 예정 수치 | 현재 상태 |
| :--- | :--- | :--- | :--- | :---: |
| **동일 PC 상용 백신 대비 비교** | Windows Defender 단독 (기본 설정) | 동일 PC에서 Defender + AegisSentinel 병행 | 동일 변종 시뮬레이터 실행 시 대응 전 변조 문서 수, 복구 후 원본 SHA-256 일치 수 | 별도 OS 프로세스 A/B 실측(`20/20 → 3/20`, 복구 `20/20`) 완료 · Defender 단독 대조 VM 시험 예정 |
| **장기 정상 작업 비용** | Defender 단독 | Defender + AegisSentinel 병행 | 개발·게임·업데이트·백업 100시간당 잘못된 강제 동결 횟수, 작업 완료 시간 증가율(%) | 1,000회 합성 워크로드 0건 완료 · 100시간 장기 텔레메트리 수집 예정 |
| **실제 OS 재부팅·전원 장애** | - | AegisSentinel 격리·복원 경로 | 실제 Windows 재부팅 및 강제 종료 반복 후 복원 성공/실패 건수 | 소프트웨어 장애 7종 + `FlushFileBuffers` 완료 · VM 재부팅 사이클 자동화 예정 |

> 본 프로젝트는 실제 별도 프로세스로 검증한 수치, 단위 규칙 기준선, 아직 측정하지 않은 장기 실환경 실험을 명확히 구분해 공개합니다.
