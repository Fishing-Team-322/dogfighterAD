# Web UI redesign — DogfighterAD

Основа: последняя загрузка `dogfighterAD-develop.zip`. SHA-256 исходного архива: `5abe5e638485a852a3d6e14abfe6e589b8ad2c73b30b0b90ebbfc3f176688965`.
Работа относится к этой выгрузке, а не к непроверенному текущему HEAD на GitHub.

## Состав изменений

Изменены семь существующих runtime-файлов в `src/DogfighterAD.Web/wwwroot/`: `index.html`, `styles.css`, `app.js`, `certificate-services-core.js`, `certificate-services.css`, `finding-presentation.js`, `finding-presentation.css`. Обновлена `docs/UI.md`. `certificate-services.js` сохранён для совместимости с существующим asset-smoke; новая HTML-страница загружает core и presentation в явном порядке через `defer`, без динамической цепочки загрузки.

Все 210 исходных файлов сохранены. Все 155 файлов C# / csproj / props побайтово совпадают с исходным архивом. Полные SHA-256 и список изменений: `validation/ui-redesign/source-integrity.json`. API, сборщик, Rule Engine, сериализация .dogad и C# presentation-mappers не изменялись. Зависимости приложения и frontend frameworks не добавлялись.

## Разделы интерфейса

| Раздел | Содержимое |
| --- | --- |
| Overview | Posture и top priorities из серверного presentation; severity counts, Informational, Not verified / Errors; метаданные снимка; переходы к findings и coverage. |
| Findings | Компактный список severity / status / title / object / reason; поиск; фильтры severity и status; reset; отдельный inspector с Overview / Technical. |
| Certificate Services | CAs, Risky templates, All templates, AD CS findings. Инвентарь слева, выбранный объект справа, поиск по имени/host/DN/OID. |
| Technical / Evidence | Collection coverage, Not verified / Errors с исходными данными evaluations, индекс attached evidence с поиском, постраничным просмотром и переходом к точному finding. |
| Import / Assessment | Все прежние поля assessment и аутентификации, import .dogad, progress, cancel и download snapshot. |

На desktop sidebar постоянная. Активный пункт отмечен фоном, левой полосой и `aria-current`. На ширине до 760 CSS px sidebar раскрывается как drawer с управлением фокусом и Escape. На ширине до 1000 px списки findings/PKI и детали показываются последовательно с Back. Табличные технические данные прокручиваются внутри своих областей.

Стиль: нейтральный светлый workspace, тёмная sidebar, единые отступы и компоненты, радиусы 3–5 px, без gradients/glass/glow/shadows и внешних шрифтов. Monospace используется для идентификаторов и технических значений. Английский язык текущего интерфейса сохранён.

## Неизменные security semantics

- В браузере не появляются новые правила, findings или security verdicts. Severity, status, confidence, validation, причины и рекомендации отображаются из прежних ответов API.
- Posture и priorities берутся исключительно из серверного `/presentation`. При недоступности этого ответа показывается исходный technical report и Retry; UI не придумывает score или трактовку состояния.
- `Risky templates` — фильтр объектов с уже выпущенными `ADCS.*` findings, не проверка флагов/ACL на frontend. `All templates` сохраняет полный инвентарь. Отсутствие finding не называется доказательством безопасности.
- `Potential`, `NotVerified`, `Error`, ограничения directory-only и отсутствие runtime verification сохранены. Счётчик `Not verified / Errors` подписан совместно, поскольку исходный серверный summary включает оба исхода; отдельно показаны исходные количества этих evaluations.
- Старые функции форматирования и отображения flags, ACL rights и NTAuth directory posture не заменены новым rule evaluation.
- Raw evidence, fact IDs, provenance, affected objects, DN, fingerprint, PKI certificate metadata, publication, EKUs, flags, periods, enrollment principals и ACL остаются доступны. Большие блоки свёрнуты через `details`, а не удалены.
- Import использует тот же POST `/api/analyze`, Content-Type, имя файла и бинарное тело. Запуск/cancel/poll/download assessment и export JSON/HTML используют прежние endpoints.
- Поле password очищается сразу после подготовки request; browser storage не добавлен.

## UI-надежность и доступность

Добавлены разделение данных разных analysisId и отбрасывание запоздавших presentation/PKI ответов, очистка устаревшей панели при неудачном импорте, retry ошибочных view-запросов, корректный переход к конкретному fingerprint из PKI и evidence. Эти изменения касаются состояния отображения, а не результатов движка.

Индекс evidence создаётся только при открытии и ограничен 100 DOM-строками на страницу. Поиск охватывает все attached facts, исходный report не мутируется. Для keyboard navigation предусмотрены focus indicators, skip link, Tab/Shift+Tab/Escape в drawer, стрелки/Home/End в tablists и возврат к выбранной строке. Полный аудит WCAG и тестирование screen reader не выполнялись.

## Выполненные проверки

Фактически выполнены **13 browser-сценариев** в headless Chromium `144.0.7559.96` с исходными статическими UI-файлами и синтетическими JSON-fixtures:

1. Пустое состояние и пять разделов; ровно один active section.
2. Импорт: прежние байты/headers; dashboard использует серверную summary; report не мутируется.
3. Поиск по presentation и technical тексту, severity/status/reset, режимы Overview/Technical.
4. Coverage, NotVerified/Error, raw evaluations, keyboard subnavigation и точный переход из evidence.
5. Evidence pagination на 251 attached facts; поиск по последней странице без потери строк.
6. CAs, risky/all templates, исходные certificate/flags details, точный переход к finding.
7. Assessment request со всеми существующими параметрами; очистка password; cancel после смены раздела.
8. Успешное завершение assessment, progress, прежний download URL и переход на Overview.
9. Неверный файл, отказ импорта, fallback technical presentation, retry presentation и PKI.
10. Отсутствующий AD CS payload и доказанный NotApplicable различаются.
11. Запоздавшие ответы предыдущего assessment не подменяют текущую view.
12. Все разделы на ширинах 320, 390, 700, 760, 768, 820, 1024, 1280, 1440 px без горизонтального переполнения body; drawer/focus/Escape; мобильные list/detail/Back.
13. HTML-подобные данные отображаются текстом, не исполняются как HTML.

Также выполнены `node --check` для всех JS-файлов, изолированная проверка URL export-dispatch, уникальность HTML IDs, отсутствие inline handlers/styles, внешних UI-ресурсов и запрещённых декоративных CSS-приёмов. Старый `<title>DogfighterAD</title>` сохранён в статическом HTML для существующего CI smoke; заголовок вкладки обновляется после JS-навигации.

Лог: `validation/ui-redesign/browser-tests.txt`. Скриншоты в `docs/ui-previews/` сделаны на synthetic fixture, это **не результаты живого AD assessment**.

### Границы проверки

.NET SDK в этой среде отсутствует. Сборка C#, xUnit, запуск ASP.NET, реальный import .dogad, загрузка/download с настоящего HTTP host и живые AD/SMB не выполнялись.

Chromium в среде блокирует URL-навигацию. Browser-suite поэтому монтирует точные локальные HTML/CSS/JS через Playwright в `about:blank` и подставляет fixture `fetch` только в тестовом контексте. Runtime-исходники не содержат mock-кода. Эти тесты проверяют DOM, UI events и request contracts, **но не HTTP delivery или исполнение серверного CSP**. Production-разметка использует только same-origin external script/style и не требует ослабления прежнего CSP. Export URL проверен изолированно в Node, не как реальная загрузка файла браузером.

## Запуск и повторение проверки

Прежний запуск приложения из корня проекта:

```powershell
dotnet run --project src/DogfighterAD.Web/DogfighterAD.Web.csproj -c Release
```

Прежние .NET проверки:

```powershell
./scripts/verify.ps1
```

или `bash scripts/verify.sh`.

Отдельная UI suite (Python 3.10+, Playwright — только dev/test-инструмент):

```bash
python -m pip install playwright
python -m playwright install chromium
python tests/Web.Ui/smoke.py --screenshots ./ui-test-output
```

При наличии системного Chromium:

```bash
python tests/Web.Ui/smoke.py --chromium /usr/bin/chromium
```

Тестовый dataset `tests/Web.Ui/fixture.json` намеренно синтетический и не является валидным .dogad. Его нельзя использовать как подтверждение результатов Rule Engine.

## Архив и патч

ZIP содержит полный проект, не только frontend. `UI_REDESIGN.patch` — unified patch для восьми изменённых существующих файлов (семь runtime assets и `docs/UI.md`) относительно присланной выгрузки. Новые tests, заметки, логи, integrity manifest и previews включены отдельно в полном дереве. Для переноса основного изменения на чистую распаковку:

```bash
git apply --check UI_REDESIGN.patch
git apply UI_REDESIGN.patch
```

Применимость патча и побайтовое совпадение восьми файлов после применения проверены отдельно. Публикация коммитов в GitHub не выполнялась.
