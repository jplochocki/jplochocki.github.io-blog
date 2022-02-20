---
title: "PyConnect na plecach GSConnect"
date: 2022-02-06T15:00:22+01:00
tags: [KDEConnect, GSConnect, Python, SSL, TLS, AnyIO, Gnome Shell]
draft: false
---


Mniej więcej na początku grudnia zainteresowałem się protokołem [KDEConnect](https://play.google.com/store/apps/details?id=org.kde.kdeconnect_tp&hl=pl&gl=US). Aplikacji tej używałem już od ponad roku - dobrze służyła mi do synchronizacji plików pomiędzy telefonem i komputerem. Coraz bardziej marzyła mi się własna wersja - po stronie komputera. Planowałem jej integrację z własnymi aplikacjami (np. automatyzację pobierania i tagowania nowych zdjęć z moich podróży).
<!--more-->

Poznanie samego protokołu [KDEConnect](https://play.google.com/store/apps/details?id=org.kde.kdeconnect_tp&hl=pl&gl=US) nie należało jednak do zadań prostych. Dokumentacja samego [KDEConnect](https://play.google.com/store/apps/details?id=org.kde.kdeconnect_tp&hl=pl&gl=US) - jest mało czytelna i nie za bogata. W zasadzie więcej o komunikacji musiałem dowiedzieć się z analizy kodu [GSConnect](https://github.com/GSConnect/gnome-shell-extension-gsconnect) (czyli rozszerzenia do [Gnome Shell](https://www.gnome.org/), które realizuje na komputerze te same zadania, co [KDEConnect](https://play.google.com/store/apps/details?id=org.kde.kdeconnect_tp&hl=pl&gl=US)). W końcu udało mi się nawiązać pierwsze połączenia z telefonem - początkowo dla uproszczenia korzystając z parowania urządzenia, jakie wykonał dla mnie sam [GSConnect](https://github.com/GSConnect/gnome-shell-extension-gsconnect).

Co mi było potrzebne (poza analizą kodu [GSConnect](https://github.com/GSConnect/gnome-shell-extension-gsconnect)) - nawiązanie połączenia przez [GSConnect](https://github.com/GSConnect/gnome-shell-extension-gsconnect). I jego wyłączenie zaraz po tym - inaczej zajmowałby on port `1716` potrzebny dla mojej aplikacji.

```sh
gnome-extensions disable gsconnect@andyholmes.github.io
ps axf | grep gsconnect | grep -v grep | awk '{print "sudo kill -9 " $1}' | sh
```

Rozszerzenie wyłączamy poleceniem `gnome-extensions disable` (`enable` pozwoli nam potem na jego włączenie). Musimy jeszcze oddzielnie zabić proces samego rozszerzenia (mający wywołanie w stylu `gjs /home/systemik/.local/share/gnome-shell/extensions/gsconnect@andyholmes.github.io/service/daemon.js`). Po tym przestanie zajmować ono nam port `1716` potrzebny do komunikacji z [KDEConnect](https://play.google.com/store/apps/details?id=org.kde.kdeconnect_tp&hl=pl&gl=US).

Z konfiguracji [GSConnect](https://github.com/GSConnect/gnome-shell-extension-gsconnect) będziemy potrzebowali certyfikatu z kluczem prywatnym dla komunikacji [TLS](https://en.wikipedia.org/wiki/Transport_Layer_Security) - są one zapisane w plikach `~/.config/gsconnect/certificate.pem` i `~/.config/gsconnect/private.pem`.

```python
import os.path


GSCONNECT_CERTFILE = os.path.expanduser(GSCONNECT_CERTFILE)
GSCONNECT_KEYFILE = os.path.expanduser(GSCONNECT_KEYFILE)

assert os.path.exists(GSCONNECT_CERTFILE) and os.path.exists(GSCONNECT_KEYFILE)
```

Drugi zestaw danych zawiera konfiguracja [dconf](https://en.wikipedia.org/wiki/Dconf) (`dconf dump /org/gnome/shell/extensions/gsconnect/`) - poniżej wynik skracam tylko do tych danych, które będą nam potrzebne:

```ini
[/]
devices=['32151f87b8be9b96']
id='112ab5c3-fd8d-4bcb-ae11-9d08fcad0a05'
name='dell'

[device/32151f87b8be9b96]
certificate-pem='-----BEGIN CERTIFICATE-----...----END CERTIFICATE-----'
name='Redmi 6A'
paired=true
```

Dane te a naszym kodzie możemy odczytać na dwa sposoby - [subprocess](https://docs.python.org/3/library/subprocess.html) i wywołanie `dconf` (np. `dconf read /org/gnome/shell/extensions/gsconnect/id`). Lub wykorzystując [Gio.Settings](https://lazka.github.io/pgi-docs/Gio-2.0/classes/Settings.html) z [PyGObject](https://pygobject.readthedocs.io/en/latest/). Ten drugi model wydał mi się trochę jednak prostszy (mimo tego, że [Gio.Settings](https://lazka.github.io/pgi-docs/Gio-2.0/classes/Settings.html) obsługuje się w sposób mało *Python-owy*). Przykład odczytywania podstawowych danych:

```python
from gi.repository import Gio


gsconnect_config = Gio.Settings.new_with_path(
    'org.gnome.Shell.Extensions.GSConnect.Device',
    '/org/gnome/shell/extensions/gsconnect/')
GSCONNECT_DEVICE_ID = gsconnect_config.get_string('id')
GSCONNECT_DEVICE_NAME = gsconnect_config.get_string('name')

# lista dostępnych ID połączeń
gsconnect_config = Gio.Settings.new_with_path(
    'org.gnome.Shell.Extensions.GSConnect',
    '/org/gnome/shell/extensions/gsconnect/')
GSCONNECT_KNOWN_DEVICES = list(gsconnect_config.get_value('devices'))
```

Przy wykonywaniu połączenia będziemy na pewno chcieli wydobyć certyfikat drugiej strony:

```python
# remote_deviceId - to id urządzenia przysłany w pakiecie identyfikacji i zapisany w dconf

gsconnect_config = Gio.Settings.new_with_path(
    'org.gnome.Shell.Extensions.GSConnect.Device',
    f'/org/gnome/shell/extensions/gsconnect/device/{remote_deviceId}/')

ssl_context.load_verify_locations(
    cadata=ssl.PEM_cert_to_DER_cert(
        gsconnect_config.get_string('certificate-pem')))
```

Analiza [GSConnect](https://github.com/GSConnect/gnome-shell-extension-gsconnect) (a dokładniej plików [src/service/core.js](https://github.com/GSConnect/gnome-shell-extension-gsconnect/blob/master/src/service/core.js) i [src/service/backends/lan.js](https://github.com/GSConnect/gnome-shell-extension-gsconnect/blob/master/src/service/backends/lan.js)) naprowadziła mnie na najbardziej podstawowy mechanizm nawiązywania połączenia:
1) Otwieramy nasłuch [UDP](https://en.wikipedia.org/wiki/User_Datagram_Protocol) na porcie `1716` (od wszystkich), czekamy na pakiet `kdeconnect.identity`. Jeśli jego nadawca (`body.deviceId`) jest nam znany - przechodzimy dalej.
2) Otwieramy połączenie ([TCP](https://en.wikipedia.org/wiki/Transmission_Control_Protocol) na porcie `1716`) z nadawcą tego pakietu.
3) Wysyłamy własny pakiet identyfikacji (`kdeconnect.identity` z naszymi danymi).
4) Zmieniamy zwykłe gniazdo [TCP](https://en.wikipedia.org/wiki/Transmission_Control_Protocol) na [TLS](https://en.wikipedia.org/wiki/Transport_Layer_Security) (ale z `server_side=True` - mimo tego, że to my nawiązaliśmy połączenie, to mamy dalej zachować się, jak serwer).
5) I możemy się cieszyć połączeniem z naszym [KDEConnect](https://play.google.com/store/apps/details?id=org.kde.kdeconnect_tp&hl=pl&gl=US).


W swoim kodzie ([pyconnect.py](https://gist.github.com/jplochocki/1a7a206ae7e2b0f2243b1fa473b31003)) będę posługiwał się biblioteką [AnyIO](https://anyio.readthedocs.io/en/stable/), która mocno upraszcza działanie z natywnym [TCP](https://en.wikipedia.org/wiki/Transmission_Control_Protocol) i [UDP](https://en.wikipedia.org/wiki/User_Datagram_Protocol), a jednocześnie umożliwia działanie w [asyncio](https://docs.python.org/3/library/asyncio.html).

Nasłuch [UDP](https://en.wikipedia.org/wiki/User_Datagram_Protocol) nie jest trudnym zadaniem, używamy [anyio.create_udp_socket()](https://anyio.readthedocs.io/en/stable/api.html#anyio.create_udp_socket), pamiętając o `local_host='255.255.255.255'` (czyli nasłuch na [broadcast](https://pl.wikipedia.org/wiki/Broadcast)) i odpowiednim `local_port` (`1716`).

```python
import anyio


KDE_CONNECT_DEFAULT_PORT = 1716


async def wait_for_incoming_id(main_group):
    async with await anyio.create_udp_socket(
            family=socket.AF_INET, local_host='255.255.255.255',
            local_port=KDE_CONNECT_DEFAULT_PORT) as udp:
        async for data, (host, port) in udp:
            try:
                pack = json.loads(data.decode('utf-8'))
            except json.JSONDecodeError:
                log.exception(('wait_for_incoming_id(): malformed id packet '
                               f'{data} from {host}:{port}'))
                return

            if pack['type'] != 'kdeconnect.identity' or 'deviceId' not in pack['body']:  # noqa
                log.warning(
                    ('wait_for_incoming_id(): identity packet without '
                     f'body.deviceId or unknown type\n{pack=}'))
                return

            dev_id = pack['body']['deviceId']
            known = dev_id in GSCONNECT_KNOWN_DEVICES
            log.info(('wait_for_incoming_id(): id packet received from '
                      f'{pack["body"]["deviceName"]} / {dev_id} (IP: {host})'
                      f'{known=}'))

            if not known or dev_id == GSCONNECT_DEVICE_ID or dev_id in CONNECTED_DEVICES:  # noqa
                return

            main_group.start_soon(device_connection_task, pack, host)
```

Odbierany pakiet będzie miał formę [JSON](https://en.wikipedia.org/wiki/JSON) - zajmującego **tylko jedną linię**. Jego przykładowa wartość wygląda następująco:

```json
{
    "id":1644153455113,
    "type":"kdeconnect.identity",
    "body":{
        "deviceId":"32151f87b8be9b96",
        "deviceName":"Redmi 6A",
        "protocolVersion":7,
        "deviceType":"phone",
        "incomingCapabilities":[
            "kdeconnect.telephony.request_mute",
            "kdeconnect.notification",
            "kdeconnect.ping",
            "kdeconnect.notification.reply",
            "kdeconnect.notification.action",
            "kdeconnect.share.request",
            "kdeconnect.bigscreen.stt",
            "kdeconnect.clipboard.connect",
            "kdeconnect.runcommand",
            "kdeconnect.connectivity_report.request",
            "kdeconnect.contacts.request_all_uids_timestamps",
            "kdeconnect.sms.request_conversations",
            "kdeconnect.telephony.request",
            "kdeconnect.mpris",
            "kdeconnect.sms.request_conversation",
            "kdeconnect.findmyphone.request",
            "kdeconnect.sms.request_attachment",
            "kdeconnect.systemvolume",
            "kdeconnect.mousepad.keyboardstate",
            "kdeconnect.sftp.request",
            "kdeconnect.share.request.update",
            "kdeconnect.notification.request",
            "kdeconnect.mousepad.request",
            "kdeconnect.photo.request",
            "kdeconnect.sms.request",
            "kdeconnect.contacts.request_vcards_by_uid",
            "kdeconnect.mpris.request",
            "kdeconnect.battery.request",
            "kdeconnect.battery",
            "kdeconnect.clipboard"
        ],
        "outgoingCapabilities":[
            "kdeconnect.telephony",
            "kdeconnect.notification",
            "kdeconnect.contacts.response_uids_timestamps",
            "kdeconnect.ping",
            "kdeconnect.share.request",
            "kdeconnect.bigscreen.stt",
            "kdeconnect.clipboard.connect",
            "kdeconnect.connectivity_report",
            "kdeconnect.sftp",
            "kdeconnect.sms.attachment_file",
            "kdeconnect.systemvolume.request",
            "kdeconnect.sms.messages",
            "kdeconnect.mpris",
            "kdeconnect.findmyphone.request",
            "kdeconnect.mousepad.keyboardstate",
            "kdeconnect.contacts.response_vcards",
            "kdeconnect.notification.request",
            "kdeconnect.mousepad.echo",
            "kdeconnect.mousepad.request",
            "kdeconnect.presenter",
            "kdeconnect.photo",
            "kdeconnect.runcommand.request",
            "kdeconnect.mpris.request",
            "kdeconnect.battery.request",
            "kdeconnect.battery",
            "kdeconnect.clipboard"
        ],
        "tcpPort":1716
    }
}
```

Co warto wiedzieć o pakietach - mają one typ (`type` - na tym etapie interesują nas tylko pakiety `kdeconnect.identity`). `id` to po prostu aktualny czas. Najciekawsze pola w `body` to `deviceId` i `deviceName` (oba będą zgodne z danymi z konfiguracji). `incomingCapabilities` i `outgoingCapabilities` to lista pluginów, jakie mogę być obsługiwane - my na początku skrócimy ją do `kdeconnect.share.request`, czyli umożliwimy tylko przesyłanie plików. W kwestii `tcpPort` - nie widziałem nigdy, aby był używany jakiś inny, niż domyślny `1716`, choć kod [GSConnect](https://github.com/GSConnect/gnome-shell-extension-gsconnect) trzyma się tego, aby nawiązywać połączenie na porcie podawanym przez ten pakiet.


Pakiet próbujemy odczytać, potem - sprawdzamy czy ma on wymagany typ i interesujące nas `body.deviceId` (z `ID`, z którym nawiązał wcześniej połączenie [GSConnect](https://github.com/GSConnect/gnome-shell-extension-gsconnect), a my te dane przechwyciliśmy z jego konfiguracji). Jak już wszystkie warunki zostaną spełnione - przechodzimy do wystartowania zadania `device_connection_task()`, które ogarnie nam temat połączenia [TCP](https://en.wikipedia.org/wiki/Transmission_Control_Protocol).

Połączenie to nawiązujemy za pomocą [anyio.connect_tcp()](https://anyio.readthedocs.io/en/stable/api.html#anyio.connect_tcp).

```python

async def device_connection_task(id_packet, remote_ip):
    async with await anyio.connect_tcp(remote_ip, KDE_CONNECT_DEFAULT_PORT) as sock:  # noqa
```

Następnie musimy w nim wysłać nasz pakiet identyfikacji:

```json
{
    "id":1644153455971504483,
    "type":"kdeconnect.identity",
    "body":{
        "deviceId":"112ab5c3-fd8d-4bcb-ae11-9d08fcad0a05",
        "deviceName":"dell",
        "deviceType":"laptop",
        "protocolVersion":7,
        "incomingCapabilities":[
            "kdeconnect.share.request"
        ],
        "outgoingCapabilities":[
            "kdeconnect.share.request"
        ],
        "tcpPort":1716
    }
}
```

`body.deviceId` i `body.deviceName` odczytaliśmy wcześniej z konfiguracji [GSConnect](https://github.com/GSConnect/gnome-shell-extension-gsconnect). `body.incomingCapabilities` i `body.outgoingCapabilities` zostały mocno skrócone - w pierwszej wersji chciałem mieć tylko przesyłanie plików (plugin [src/service/plugins/share.js](https://github.com/GSConnect/gnome-shell-extension-gsconnect/blob/master/src/service/plugins/share.js) wymagający tylko wartości `kdeconnect.share.request`). Generowanie tego pakietu w kodzie wygląda następująco:


```python
PROTOCOL_VERSION = 7
INCOMING_CAPABILITIES = [
    'kdeconnect.share.request',
]
OUTGOING_CAPABILITIES = [
    'kdeconnect.share.request',
]


def generate_my_identity():
    return {
        'type': 'kdeconnect.identity',
        'body': {
            'deviceId': GSCONNECT_DEVICE_ID,
            'deviceName': GSCONNECT_DEVICE_NAME,
            'deviceType': 'laptop',
            'protocolVersion': PROTOCOL_VERSION,
            'incomingCapabilities': INCOMING_CAPABILITIES,
            'outgoingCapabilities': OUTGOING_CAPABILITIES,
            'tcpPort': KDE_CONNECT_DEFAULT_PORT
        }
    }


def prepare_to_send(pack):
    pack2 = pack.copy()
    pack2['id'] = time.time_ns()
    return (json.dumps(pack2) + '\n').encode('utf-8')


# wysyłanie w device_connection_task()
        await sock.send(prepare_to_send(generate_my_identity()))
```

Po wysłaniu pakietu identyfikacji - musimy przekształcić nasze gniazdo w [TLS](https://en.wikipedia.org/wiki/Transport_Layer_Security) (za pomocą [TLSStream.wrap()](https://anyio.readthedocs.io/en/stable/api.html#anyio.streams.tls.TLSStream.wrap) z [AnyIO](https://anyio.readthedocs.io/en/stable/), pamiętając, że protokół [KDEConnect](https://play.google.com/store/apps/details?id=org.kde.kdeconnect_tp&hl=pl&gl=US) wymaga od nas zachowywania się jak strona serwera - `server_side=True`). Kontekst [TLS](https://en.wikipedia.org/wiki/Transport_Layer_Security) - musi zawierać pliki certyfikatu i klucza przechwycone z [GSConnect](https://github.com/GSConnect/gnome-shell-extension-gsconnect) i mieć załadowany certyfikat urządzenia (odczytany z konfiguracji [GSConnect](https://github.com/GSConnect/gnome-shell-extension-gsconnect)):

```python
from anyio.streams.tls import TLSStream, TLSListener


    # ...
    remote_deviceId = id_packet['body']['deviceId']

    ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ssl_context.load_cert_chain(GSCONNECT_CERTFILE, GSCONNECT_KEYFILE)
    ssl_context.verify_flags = ssl.CERT_REQUIRED

    gsconnect_config = Gio.Settings.new_with_path(
        'org.gnome.Shell.Extensions.GSConnect.Device',
        f'/org/gnome/shell/extensions/gsconnect/device/{remote_deviceId}/')

    ssl_context.load_verify_locations(
        cadata=ssl.PEM_cert_to_DER_cert(
            gsconnect_config.get_string('certificate-pem')))

    # ...
    async with await anyio.connect_tcp(remote_ip, KDE_CONNECT_DEFAULT_PORT) as sock:  # noqa
        # ... po wysłaniu pakietu ID

        ssock = await TLSStream.wrap(sock, server_side=True,
                                     ssl_context=ssl_context)
```

Po poprawnym przekształceniu połączenia na [TLS](https://en.wikipedia.org/wiki/Transport_Layer_Security) - możemy czekać na pakiety od [KDEConnect](https://play.google.com/store/apps/details?id=org.kde.kdeconnect_tp&hl=pl&gl=US). Dla uproszczenie użyłem [BufferedByteReceiveStream](https://anyio.readthedocs.io/en/stable/api.html#anyio.streams.buffered.BufferedByteReceiveStream), który ułatwia czekanie na koniec pakietu - każdy pakiet to [JSON](https://en.wikipedia.org/wiki/JSON) przesyłany w **jednej linii** - czekamy więc na kolejne `'\n'`.

```python
from anyio.streams.buffered import BufferedByteReceiveStream

        # ...
        bssock = BufferedByteReceiveStream(ssock)
        
        while True:
            pack_data = await bssock.receive_until(b'\n', 1024 * 1024)

            try:
                pack = json.loads(pack_data)
            except json.JSONDecodeError:
                log.exception(
                    ('device_connection_task(): Error while decoding '
                     f'packet / {pack_data}'))
                continue
            log.debug(f'device_connection_task(): Packet {pack_data}')
            
            
            # obsługa samego pakietu

```

Wspominany tu kod znajduje się w pliku [pyconnect.py](https://gist.github.com/jplochocki/1a7a206ae7e2b0f2243b1fa473b31003).


W [następnym poście]({{< ref "/post/2022-02-20-pyconnect-i-pliki.md" >}}) przedstawię mechanizm odbierania i wysyłania plików.
