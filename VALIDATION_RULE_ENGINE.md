# Rule Engine — выполненная проверка поставки

Основа: последняя загрузка `dogfighterAD-main(2).zip`. Эта поставка не подменяет её предыдущими архивами foundation/fixed.

**Сборка C#, restore NuGet, xUnit и проверки на живом AD/SMB не выполнялись: в рабочей среде отсутствует .NET SDK.** Наличие тестов и статических проверок не является утверждением об успешной компиляции или готовности к production.

## Что действительно проверено

| Проверка | Результат |
| --- | --- |
| Лексический просмотр C# через Pygments | 124 файла, 0 токенов ошибки; это не компилятор и не Roslyn |
| Разбор XML проектов и общего props | 8 файлов успешно прочитаны |
| Ссылки ProjectReference | Все целевые проекты существуют |
| JSON примеров и YAML workflow | Синтаксический разбор успешен |
| Исходный каталог правил | 80 уникальных ID, все представлены в `docs/RULES.md` |
| Маркеры незавершённых merge-конфликтов | В C# не обнаружены |
| Выбранные маркеры сетевого доступа и текущего wall-clock в Application/Analysis | Не обнаружены; проверка не заменяет полноценный анализ зависимостей |
| `bash scripts/verify.sh` | Фактически запущен; остановлен с кодом **127** до restore/build/test: SDK отсутствует |

Машиночитаемая запись: [`validation/rule-engine-static.json`](validation/rule-engine-static.json).
Проверка применимости патча и точного совпадения исходников записана отдельно в [`validation/rule-engine-packaging.json`](validation/rule-engine-packaging.json).

## Написанные тесты — не результаты запуска

Добавлены 19 `[Fact]`-методов, 69 строк `InlineData` и 324 сценария из генераторов `MemberData`: всего **412 сценариев по статическому подсчёту исходников**. xUnit discovery и выполнение здесь не запускались. Это не 412 успешно пройденных тестов.

Тестовые файлы находятся в `tests/DogfighterAD.Core.Tests/Analysis/` и покрывают семейства правил, отсутствующие/неверные/скрытые/противоречивые факты, версии контрактов, доказательства членств, циклы групп, сохранение исходного типа реестра, детерминизм, JSON/HTML, CLI и новые поля коллектора. Изменены ожидания production composition в существующем наборе тестов.

Ни вымышленные TRX/XML-результаты, ни якобы собранные бинарные файлы в архив не включены.

## Проверка после распаковки

Требуется .NET 10 SDK и доступ к источникам NuGet для restore. Существующие версии зависимостей сохранены.

PowerShell:

```powershell
./scripts/verify.ps1
```

Linux/macOS:

```sh
bash scripts/verify.sh
```

Эквивалентные команды для используемого в проекте исполняемого xUnit v3/Microsoft Testing Platform runner:

```sh
dotnet restore tests/DogfighterAD.Core.Tests/DogfighterAD.Core.Tests.csproj
dotnet build tests/DogfighterAD.Core.Tests/DogfighterAD.Core.Tests.csproj -c Release --no-restore
dotnet run --project tests/DogfighterAD.Core.Tests/DogfighterAD.Core.Tests.csproj -c Release --no-build
dotnet run --project src/DogfighterAD.Cli/DogfighterAD.Cli.csproj -c Release --no-build -- rules --format json
```

CI выполняет build/test на Windows и Ubuntu; добавлен smoke-вызов офлайн-каталога. Изменение workflow в архиве не означает, что удалённый CI уже был запущен.

## Критерии приёмки на стенде

Проверить на известной конфигурации AD: domain defaults и отдельную PSO, права чтения их полей, nonempty/empty GPP signal, исходный REG_DWORD в Registry.pol и security template, ACL с object-specific ACE и порядок, группы с диапазонами/primary group/циклом. Сверить доказательства с исходными настройками и числом объектов. Затем повторить анализ со скрытыми атрибутами и частичным сбором: ожидается `NotVerified`/`Partial`, а не чистый результат.

Отдельно измерить память и время на реальном объёме снимка: ограничение размера артефакта/числа evaluations не является доказанным общим лимитом working set.

GPO/ACE-кандидаты не являются расчётом эффективных прав или результирующей политики. Per-user resultant PSO, RSoP, AD CS, RBCD и LAPS не реализованы и не имитируются правилами-заглушками. См. [docs/RULE_ENGINE.md](docs/RULE_ENGINE.md).
