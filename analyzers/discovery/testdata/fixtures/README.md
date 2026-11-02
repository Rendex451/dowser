# Фикстуры ответов сервисов

Сырые ответы настоящих сервисов, записанные 2026-11-02 из контейнеров.
Расширение — что именно сделано после подключения:

- `.greeting` — подключились и ждали до 3 с, ничего не отправляя;
- `.get` — отправили `GET / HTTP/1.0\r\n\r\n` и читали до закрытия или 3 с;
- `.tls-get` — то же внутри TLS (сертификат не проверялся).

Читалось не больше 8 КБ.

| Файл | Источник |
|---|---|
| `openssh-9.greeting`, `openssh-9.get` | `linuxserver/openssh-server:latest`, порт 2222 |
| `vsftpd-3.greeting` | `delfer/alpine-ftp-server:latest`, порт 21 (баннер изменён автором образа, версии нет) |
| `mailpit.greeting`, `mailpit-ui.get` | `axllent/mailpit:latest`, порты 1025 и 8025 |
| `dovecot-imap.greeting` | `dovecot/dovecot:latest` (2.4.5), порт 31143 |
| `dovecot-pop3.greeting` | `alpine:3.20` + пакеты `dovecot dovecot-pop3d`, порт 110 |
| `busybox-telnetd.greeting` | `alpine:3.20` + `busybox-extras`, `telnetd -p 23` |
| `mariadb-11.greeting` | `mariadb:11` (11.8.9), порт 3306 |
| `x11vnc.greeting` | `alpine:3.20` + `x11vnc xvfb`, порт 5900 |
| `rsyncd.greeting` | `alpine:3.20` + `rsync --daemon`, порт 873 |
| `ergo-irc.get` | `ghcr.io/ergochat/ergo:stable`, порт 6667 (при подключении молчит) |
| `nginx-1.27.get` | `nginx:1.27-alpine`, порт 80 |
| `redis-7.get` | `redis:7-alpine`, порт 6379 |
| `elasticsearch-8.get` | `elasticsearch:8.15.3`, `xpack.security.enabled=false`, порт 9200 |
| `k3s-apiserver.tls-get` | `rancher/k3s:v1.31.2-k3s1`, порт 6443 |
