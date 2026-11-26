# AegisSentinel 정량 평가 및 재현 가능 벤치마크 (Benchmarks)

이 문서는 **“AegisSentinel을 추가했을 때 실제 사용자 문서 피해가 얼마나 줄었는가, 정상 작업 비용은 얼마인가, 장애 시에도 사용자 데이터가 남는가”**라는 세 가지 핵심 질문에 재현 가능한 수치로 답하기 위한 평가 프로토콜과 실측 결과를 기록합니다.

---

## 1. 재현 방법 (누구나 동일 조건으로 실행 가능)

모든 자동화 벤치마크는 격리된 `%TEMP%\AegisBench_*` 디렉터리에서만 실행되며 사용자의 실제 파일이나 시스템 설정을 건드리지 않습니다.

```powershell
# 1. 클린 Release 빌드 (-warnaserror)
dotnet build AegisSentinel.slnx -c Release --no-incremental -warnaserror

# 2. 3대 핵심 지표 벤치마크 실행 (실측 수치 출력)
dotnet test tests/AegisSentinel.Tests/AegisSentinel.Tests.csproj -c Release --no-build --filter "FullyQualifiedName~RansomwareDefenseBenchmarkTests" --logger "console;verbosity=detailed"
```

---

## 2. 자동화 벤치마크 실측 결과 (Windows 11 x64 · .NET 10 Release)

| 평가 질문 | 벤치마크 테스트 | 측정 지표 | 실측 결과 |
| :--- | :--- | :--- | :---: |
| **1. 문서 피해 최소화 & 복구율** | `Benchmark_01_RansomwareDocumentProtection` | 보호 문서 50개 모의 랜섬웨어 공격 시 미보호 기준 피해 | `50 / 50` 변조 |
| | | AegisSentinel 탐지·동결 전 변조 문서 수 (미끼 파일 선탐지) | **`0 / 50`** |
| | | 탐지 지연 시간 (`DetectionLatencyMs`) | **`20 ms`** |
| | | 복구 후 원본 SHA-256 일치율 (`RecoveryVault`) | **`50 / 50 (100%)`** |
| **2. 정상 작업 비용 & 오동결** | `Benchmark_02_NormalWorkflowOverhead` | 개발·브라우저/게임·스크립트·대량 복사 정상 작업 1,000회 | 오동결 **`0 / 1,000`** |
| | | 정상 작업 오탐 경고 수 (`FalseAlerts`) | **`0 / 1,000`** |
| | | 1,000회 누적 평가 시간 / 평균 지연 | **`155 ms`** (`155.02 µs/op`) |
| **3. 장애 시 사용자 데이터 보존** | `Benchmark_03_FaultResilienceMatrix` | 6대 주입 장애(디스크 부족·삭제 직후 중단·OS 배타적 잠금·복원 충돌·재부팅 삭제 취소 실패·격리 중 64 MiB 경계 초과 파일 증가) | **`6 / 6 (100% 무손실)`** |

---

## 3. 실환경 장기 비교 평가 프로토콜 (다음 이정표)

위 자동화 벤치마크는 단위·통합 레벨에서 누구나 10초 이내에 재현할 수 있는 결정적 기준선입니다. 상용 솔루션 대비 실질적 우위를 입증하기 위한 다음 단계 실환경 비교 기준은 다음과 같이 분리해 관리합니다.

| 비교 항목 | 대조군 (Baseline) | 실험군 (Treatment) | 공개 예정 수치 | 현재 상태 |
| :--- | :--- | :--- | :--- | :---: |
| **동일 PC 모의 랜섬웨어 비교** | Windows Defender 단독 (기본 설정) | 동일 PC에서 Defender + AegisSentinel 병행 | 대응 전 변조 문서 수, 복구 후 원본 SHA-256 일치 문서 수 | 자동화 시뮬레이터 기준선 완료 · 격리 VM 실측 비교 예정 |
| **장기 정상 작업 비용** | Defender 단독 | Defender + AegisSentinel 병행 | 개발·게임·업데이트·백업 100시간당 잘못된 강제 동결 횟수, 작업 완료 시간 증가율(%) | 1,000회 합성 워크로드 0건 완료 · 100시간 장기 텔레메트리 수집 예정 |
| **실제 OS 재부팅·전원 장애** | - | AegisSentinel 격리·복원 경로 | 실제 Windows 재부팅 및 강제 종료 반복 후 복원 성공/실패 건수 | 소프트웨어 장애 6종 + `FlushFileBuffers` 완료 · VM 재부팅 사이클 자동화 예정 |

> 본 프로젝트는 자동화로 실측한 수치와 아직 측정하지 않은 장기 실환경 실험을 명확히 구분해 공개합니다.
