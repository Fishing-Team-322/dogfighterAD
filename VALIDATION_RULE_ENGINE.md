# Rule Engine — фактический статус проверки

Этот документ отражает уже выполненную проверку Rule Engine milestone после интеграции исходного пакета, исправления контрактов evidence/absence и live MINILAB прогона.

## Текущий validated baseline

Проверенный feature head перед merge:

`13bcf2072f59506df6cafa489725cbe254ad6833`

Merge в `foundation/snapshot-core`:

`00a905a0b571957e581f22a6501dcfa26d081a9e`

Promotion в `main`:

`4514c187a4d7e7f3af2c568473fb665698059ad4`

## Что фактически проверено

| Проверка | Результат |
| --- | --- |
| .NET restore/build на Windows | Успешно |
| Локальный `scripts/verify.ps1` | 678 тестов, 0 errors, 0 failed, 0 skipped |
| Каталог правил | `dogfighterad.core/1.0.0`, 80 rule IDs, exit 0 |
| GitHub CI feature head | Windows + Ubuntu build/test/catalog smoke — success |
| Self-contained Windows publish smoke | success |
| Live `audit-full` на MINILAB с WORKGROUP Windows host | Complete, exit 0 |
| LDAP auth/protection | Negotiate + sign/seal, exact FQDN server |
| Explicit-credential SYSVOL | Portable Kerberos, application-owned SMB path |
| Collection coverage | Все запрошенные capabilities Complete, issues=0 |
| Offline analysis | 80 rules evaluated; JSON/HTML reports generated |
| Missing-evidence semantics | Не наблюдавшиеся поля остаются `NotVerified`, не подменяются defaults |

## Live MINILAB Rule Engine acceptance

Свежий `audit-full` snapshot был собран с explicit credential `MINILAB\alice` против `dc.mini.lab` с hidden password prompt и portable Kerberos SYSVOL.

Collection result:

- snapshot status: `Complete`;
- target: `dc.mini.lab`;
- domains=1;
- users=8;
- groups=50;
- computers=2;
- ous=1;
- memberships=41;
- gpos=2;
- все directory/GPO/SYSVOL capabilities: `Complete`;
- collection issues: 0;
- exit code: 0.

После исправления evidence contracts/LDAP attribute absence proof итоговый offline analysis показал:

- rules: 80;
- findings: 22;
- `Present`: 8;
- `Potential`: 14;
- `NotDetected`: 529;
- `NotApplicable`: 75;
- `NotVerified`: 2;
- `Error`: 0.

Оставшиеся два `NotVerified` относятся только к `AD.USER.REPLICATED_LOGON_AGE` для пользователей `bob` и `dave`, где `user.lastLogonTimestamp` действительно не был наблюдён. Это считается корректным fail-closed результатом, а не дефектом, который нужно скрывать ради `not-verified=0`.

Findings по severity в этом стенде:

- High: 9;
- Medium: 12;
- Low: 1.

Конкретные findings отражают состояние лаборатории и не являются универсальным baseline для других доменов.

## CI после последнего evidence fix

Feature commit `13bcf2072f59506df6cafa489725cbe254ad6833` прошёл GitHub CI полностью:

- Ubuntu restore/build/unit tests/rule catalog smoke — success;
- Windows restore/build/unit tests/rule catalog smoke — success;
- Windows self-contained publish smoke — success.

После merge в foundation отдельный promotion PR в `main` также прошёл отдельный CI перед merge.

## Старое static-only происхождение

Исходный импорт Rule Engine сопровождался статическими packaging-проверками до наличия .NET SDK в authoring environment. Эти записи сохранены только как provenance:

- [`validation/rule-engine-static.json`](validation/rule-engine-static.json)
- [`validation/rule-engine-packaging.json`](validation/rule-engine-packaging.json)

Они больше не являются главным источником статуса готовности. Фактическая build/test/live validation выше имеет приоритет.

## Что ещё не проверено

- Live Linux Kerberos/SMB SYSVOL path остаётся pending.
- Fuller GOAD end-to-end acceptance остаётся pending.
- LDAP request/page budgets и peak-memory/resource thresholds ещё не измерены на нескольких размерах каталогов.
- GPO/ACE rules не являются полным RSoP/effective-rights engine.
- Per-user resultant PSO, AD CS, RBCD, LAPS, full attack-path graph analysis и multi-domain/forest assessment остаются будущими milestones.

## Повторяемая локальная проверка

PowerShell:

```powershell
./scripts/verify.ps1
```

Каталог правил:

```powershell
./src/DogfighterAD.Cli/bin/Release/net10.0/dogfighter.exe rules
```

Offline analysis:

```powershell
./src/DogfighterAD.Cli/bin/Release/net10.0/dogfighter.exe analyze `
  --snapshot .\audit.dogad `
  --output .\analysis.json `
  --fail-on none
```

Для exact semantics см. [`docs/RULE_ENGINE.md`](docs/RULE_ENGINE.md) и [`docs/CLI.md`](docs/CLI.md).
