# AegisSentinel 기여 가이드 (Contributing Guide)

AegisSentinel 프로젝트에 관심을 가져 주셔서 감사합니다. 일관된 코드 품질과 높은 보안 신뢰성을 유지하기 위해 아래 규칙에 따라 작업합니다.

---

## 1. 브랜치 전략

- `main`: 항상 클린 빌드(`-warnaserror`)와 전체 회귀 테스트가 통과하는 안정 브랜치
- 기능 개발: `feat/<간단한-설명>` (예: `feat/etw-amsi-provider`)
- 버그·보안 수정: `fix/<간단한-설명>` (예: `fix/quarantine-atomic-restore`)
- 문서·테스트 개선: `docs/<설명>`, `test/<설명>`

---

## 2. 커밋 메시지 규칙 (Conventional Commits)

커밋 메시지는 **Conventional Commits** 형식을 따르며, 한국어로 명확하게 작성합니다.

| 접두사 | 용도 | 예시 |
| :--- | :--- | :--- |
| `feat:` | 새로운 탐지 엔진·기능 추가 | `feat: NTFS ADS 숨김 스트림 스캐너 추가` |
| `fix:` | 버그 수정·오탐 개선·보안 패치 | `fix: 단일 핸들 생성시각 검증으로 PID 재사용 오종료 차단` |
| `refactor:` | 동작 변경 없는 구조 개선 | `refactor: 경고 대기열 로직을 ThreatPromptQueueCoordinator로 분리` |
| `perf:` | 성능·메모리 최적화 | `perf: 스트리밍 BFS로 대용량 검사 메모리 O(1) 유지` |
| `test:` | 회귀 테스트 및 벤치마크 추가 | `test: 실제 Win32 프로세스 동결·재개 통합 테스트 추가` |
| `docs:` | 문서 및 변경 이력 업데이트 | `docs: CHANGELOG 및 보안 정책 문서 추가` |
| `chore:` | 빌드·CI·저장소 설정 관리 | `chore: .editorconfig 및 GitHub 템플릿 추가` |

---

## 3. 개발 및 검증 체크리스트 (필수)

모든 코드 변경은 **TDD(실패하는 회귀 테스트 먼저 작성 → 수정 → 전체 통과)** 원칙을 따르며, PR·푸시 전 아래 검증을 모두 통과해야 합니다.

```powershell
# 1. 클린 Release 빌드 (경고 0건 필수)
dotnet build AegisSentinel.slnx -c Release --no-incremental -warnaserror

# 2. 전체 단위 · 레드팀 · 실환경 회귀 테스트 실행
dotnet test tests/AegisSentinel.Tests/AegisSentinel.Tests.csproj -c Release --no-build --verbosity normal

# 3. Windows Defender 빌드 산출물 오탐 검사
& "$env:ProgramFiles\Windows Defender\MpCmdRun.exe" -Scan -ScanType 3 -File "src\AegisSentinel.App\bin\Release\net10.0-windows" -DisableRemediation
```

### 보안·안전 필수 가드레일
- 테스트는 반드시 격리된 `%TEMP%\Aegis*` 임시 디렉터리와 테스트 대역/무해한 자식 프로세스만 사용하며, 종료 시 100% 정리되어야 합니다.
- 사용자의 실제 문서, 시스템 핵심 바이너리(`C:\Windows\System32` 등), 호스트 IDE 프로세스는 절대 자동 격리·종료되지 않아야 합니다.
- 외부에 드러나는 동작 변경·버그 수정·기능 추가는 반드시 [CHANGELOG.md](CHANGELOG.md)에 함께 기록합니다.

---

## 4. 릴리스 및 버전 관리 (SemVer)

- [Semantic Versioning 2.0.0](https://semver.org/lang/ko/) (`MAJOR.MINOR.PATCH`)을 따릅니다.
- 릴리스 시 `CHANGELOG.md`의 `[Unreleased]` 항목을 해당 버전과 날짜로 확정하고, Git Annotated Tag (`vX.Y.Z`)와 GitHub Release를 함께 발행합니다.
