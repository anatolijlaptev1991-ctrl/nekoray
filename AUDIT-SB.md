# Аудит миграции sing-box 1.9.7 → 1.13.21 (ветка feature/singbox-upgrade)

Дата: 2026-09-16.

## Состав изменений

### Репозиторий anatolijlaptev1991-ctrl/sing-box (ветка neko-1.13)
База: апстрим SagerNet/sing-box v1.13.21. Коммиты:
1. `22a6008c` — neko-слой:
   - `cmd/sing-box/*`: package main → **package boxmain** (37 файлов) — ядро становится импортируемой библиотекой; `main()` → `Main()`;
   - `cmd/sing-box/neko_run.go`: `Create(configBytes)` (парсинг → box.New → Start) и `SetDisableColor`;
   - `box_neko.go`: `SetLogWritter` (подмена writer'а лог-фабрики, reflect-хак как в форке 1.9 — поле `writer` у `defaultFactory` сохранено в 1.13), `NekoDialContext`/`NekoDialUDP` через default outbound;
   - `boxapi/`: `go_http.go` (HTTP-клиент через инстанс), `go_net.go` (DialContext/DialUDP), `stats.go` (обёртка над upstream experimental/v2rayapi: NewStatsService + QueryStats);
2. `2f36c711` — Version = "1.13.21-neko.1".

Из 6 функциональных патчей старого форка перенесены 3; 3 не требуются:
- block-blackhole (120b5c38): outbound/block.go переехал в protocol/block, патч-поведение покрыто апстримом;
- hysteria hop (33ab8e31): port hopping уже в апстриме 1.13 (server_ports/hop_interval);
- selector callback (nekoutils): не используется ни NekoBox, ни libneko.

### Репозиторий anatolijlaptev1991-ctrl/nekoray (ветка feature/singbox-upgrade)
- `libs/get_source.sh`: клон sing-box → наш форк; блок клонирования sing-quic удалён (модуль берётся из прокси-кэша Go по версии из go.mod 1.13);
- `libs/get_source_env.sh`: COMMIT_SING_BOX → 2f36c711; COMMIT_SING_QUIC удалён;
- `libs/build_go.sh`: тег `with_ech` удалён (в 1.13 ECH в stdlib, тег вызывает ошибку компиляции);
- `go/cmd/nekobox_core/go.mod`: убран replace sing-quic; go.sum перегенерирован (go mod tidy, Go 1.24.7);
- `go/cmd/nekobox_core/grpc_box.go`: статистика через `Router().AppendTracker(v2rayapi.NewStatsService(...))` вместо SetV2RayServer (SetV2RayServer удалён из роутера в 1.13; AppendTracker — официальный механизм); QueryStats через boxapi-обёртку; сброс statsService в Stop;
- `go/cmd/nekobox_core/main.go`, `core_box.go`, `update.go`: без изменений API (совместимы);
- CI workflow: Go 1.22.12 → 1.24.7 (минимальная версия go.mod sing-box 1.13); триггер push добавлен для feature/singbox-upgrade;
- `db/ConfigBuilder.cpp` (схема конфига):
  - geosite:/geoip: элементы правил конвертируются в `rule_set` (remote .srs SagerNet, download_detour direct, дедупликация); правила с geosite/geoip в 1.12+ вызывают жёсткую ошибку;
  - в route добавлены `rule_set` (определения) и `default_domain_resolver` (dns-direct + outbound strategy) — обязательно в 1.12+ для резолва доменов наружу;
  - outbound `dns-out` удалён (тип "dns" удалён в 1.13); hijack-правило переведено на `{"action":"hijack-dns"}`;
  - inbound-поля sniff/sniff_override_destination/domain_strategy удалены (убраны из 1.13); sniff перенесён в route-действие `{"action":"sniff","inbound":[...]}` в начале правил;
  - TUN inet4_address/inet6_address → `address` (массив; удалены в 1.12);
  - route.geoip/route.geosite объекты удалены (больше не влияют);
  - legacy-DNS (servers с address:, rcode://, fakeip, independent_cache) сохранён как есть — 1.13 содержит автоматический upgrade-слой (deprecation-предупреждения при старте; фактическая миграция формата потребуется к sing-box 1.14);
  - `WriteVPNSingBoxConfig` + `res/vpn/sing-box-vpn.json`: TUN-адреса переведены на `address` (плейсхолдер %TUN_ADDRESS%).

## Валидация

- `go vet` + `go test ./happ/` (38 legacy + salted векторов) — зелёные;
- `go build` с тегами with_clash_api,with_gvisor,with_quic,with_wireguard,with_utls — успешно ( nekobox_core 53.6 МБ);
- CI: полный цикл windows64 — успешно;
- `nekobox_core check` (валидатор 1.13) на двух репрезентативных конфигах:
  1. полный: mixed+tun, legacy DNS (+fakeip, rcode, independent_cache), rule_set правила (geosite/geoip), sniff action, hijack-dns, mux-vmess, default_domain_resolver, clash_api — **exit 0** (4 deprecation WARN по legacy DNS — допустимо для 1.13);
  2. матрица протоколов: vless(reality+uTLS+flow), trojan, ss-2022, hysteria2(server_ports), tuic, socks, http, direct, block — **exit 0**;
- установленная тестовая копия: `nekobox_core version` → `sing-box: 1.13.21-neko.1 NekoBox: nekoray-4.0.1-happ.2-sb113`; happ-salted декрипт — корректен.

## Известные ограничения

1. Legacy-DNS секция конфига держится на compat-слое 1.13 и будет удалена в 1.14 — к миграции на 1.14 нужен перевод генерации DNS в новый формат (функция `use_dns_object` в настройках уже позволяет задать DNS вручную).
2. `sniff_override_destination` (подмена адреса на снифнутый домен) в новом механизме сниффинга не существует — поведение соотв. современному sing-box.
3. Remote rule-set'ы требуют доступности raw.githubusercontent.com при первом старте (далее кэш в cache_file); без сети и кэша правила с rule-set не применяются.
4. Статистика трафика считается через официальный v2ray-stats-трекер апстрима (поведение прежнее: счётчики outbound>>>tag>>>traffic>>>uplink/downlink).

## Не изменено
Профили/настройки (формат NekoBox), happ-функции, механизм обновления, updater, GUI — не тронуты (кроме перечисленного).
