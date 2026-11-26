# 보안 정책 (Security Policy)

AegisSentinel은 엔드포인트 보안 도구 특성상 보안 취약점 및 우회 기법 제보를 최우선으로 다룹니다.

## 지원 버전 (Supported Versions)

현재 보안 패치가 제공되는 버전은 다음과 같습니다.

| 버전 | 보안 패치 지원 여부 |
| :--- | :---: |
| `1.1.x` (최신 `main`) | ✅ 지원 |
| `1.0.x` | ⚠️ 최신 `1.1.x` 업그레이드 권장 |
| `< 1.0.0` | ❌ 미지원 |

## 보안 취약점 제보 방법 (Reporting a Vulnerability)

**권한 상승, 격리소 탈출(Symlink/Path Traversal), 자가방어 우회, 오종료/DoS 등 보안 취약점은 공개 GitHub Issue로 등록하지 말아 주세요.**

1. GitHub 저장소의 **Security → Advisories → Report a vulnerability** (Private Vulnerability Reporting)를 통해 비공개로 제보해 주세요.
2. 가능하면 다음 정보를 함께 전달해 주시면 빠르게 재현·수정할 수 있습니다.
   - 영향받는 커밋 해시 또는 릴리스 버전
   - 취약점 유형 및 재현 단계 (안전한 최소 PoC 또는 테스트 케이스)
   - 예상 영향 범위 (예: Ring-3 권한 상승, 오탐/미탐 우회, 격리 파일 손상 등)
3. 제보 접수 후 **72시간 이내**에 수신 확인을 드리며, 수정 패치와 회귀 테스트 검증이 완료된 뒤 릴리스 노트와 함께 공개합니다.

## 위협 모델 및 보안 경계

AegisSentinel은 **Windows 유저모드(Ring-3) + 관리자 권한**으로 동작합니다. 커널 드라이버(Ring-0)가 없는 환경에서 구조적으로 존재하는 경계(BYOVD, SYSTEM 탈취 시 PPL 부재 등)와 보완 전략은 [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md)에 투명하게 문서화되어 있습니다.

## 오탐(False Positive) 제보

정상 프로그램이 오탐지되거나 불필요하게 동결된 경우에는 보안 취약점이 아니므로 [버그·오탐 제보 이슈 템플릿](.github/ISSUE_TEMPLATE/bug_report.yml)을 통해 편하게 등록해 주세요.
