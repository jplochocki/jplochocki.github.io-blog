---
title: "PyConnect i pliki"
date: 2022-02-20T08:47:44+01:00
tags: [KDEConnect, GSConnect, Python, SSL, TLS, AnyIO]
draft: false
---

W [poprzednim poście]({{< ref "/post/2022-02-06-pyconnect-na-plecach-gsconnect.md" >}})
opisałem nawiązywanie połączenia z [KDEConnect](https://play.google.com/store/apps/details?id=org.kde.kdeconnect_tp&hl=pl&gl=US)
(przy wykorzystaniu danych z [GSConnect](https://github.com/GSConnect/gnome-shell-extension-gsconnect)).
Teraz czas na przedstawienie, jak działa jedna z najbardziej podstawowych
funkcjonalności tego protokołu - czyli możliwość przesyłania plików. A możemy
je odbierać, jak i [wysyłać]({{< relref "#wysyłanie-plików" >}}).
<!--more-->

Odbieranie plików
-----------------
<div style="float: right; width: 410px;">

![KDE Connect i wysyłanie plików](/2022-02-20-pyconnect-i-pliki-1.jpg)

</div>

Odbieranie plików inicjuje oczywiście [KDEConnect](https://play.google.com/store/apps/details?id=org.kde.kdeconnect_tp&hl=pl&gl=US).
Z dostępnych opcji wybieramy "**Wysyłanie plików**" (pojawi się dialog wyboru
plików, z którego możemy wybrać jeden lub więcej plików do przesłania).

[KDEConnect](https://play.google.com/store/apps/details?id=org.kde.kdeconnect_tp&hl=pl&gl=US)
w takiej sytuacji wysyła do naszego urządzenia pakiet `kdeconnect.share.request`
zawierający w `body` informacje o pliku, jak jego nazwa - `filename`.
W kwestii rozmiaru pliku, korzystamy z `payloadSize` z poza `body`.

```json
{
    "id": 1645343489598,
    "type": "kdeconnect.share.request",
    "body":{
        "filename": "Screenshot_2022-02-07-23-30-00-849_com.facebook.lite.jpg",
        "lastModified": 1644273001000,
        "numberOfFiles": 2,
        "totalPayloadSize": 310309
    },
    "payloadSize": 260509,
    "payloadTransferInfo": {
        "port": 1739
    }
}
```

Transfer pliku nie jest prowadzony w tym samym połączeniu, które przesyła nam
pakiety, ale w nowym połączeniu, które powinniśmy nawiązać z [KDEConnect](https://play.google.com/store/apps/details?id=org.kde.kdeconnect_tp&hl=pl&gl=US)
na porcie podanym w `payloadTransferInfo.port` (numer portu będzie pomiędzy
`1739` a `1764`).

W przypadku wysyłania wielu plików - będziemy mieli przesyłane kolejne pakiety
`kdeconnect.share.request` (następny po zakończeniu pobierania pliku wskazanego
przez poprzedni pakiet). Na wysyłanie wielu plików wskazują nam pola
`body.numberOfFiles` (ilość plików przesyłanych) i `body.totalPayloadSize` (suma
wielkości wszystkich plików; `payloadSize` to wielkość pojedynczego pliku). Np.
następny plik po tym będzie miał następujący pakiet `kdeconnect.share.request`:


```json
{
    "id": 1645343489646,
    "type": "kdeconnect.share.request",
    "body":{
        "filename": "Screenshot_2022-02-20-08-51-10-065_org.kde.kdeconnect_tp.jpg",
        "lastModified": 1645343471000,
        "numberOfFiles": 2,
        "totalPayloadSize": 310309
    },
    "payloadSize": 49800,
    "payloadTransferInfo": {
        "port": 1739
    }
}
```

Po teorii - czas na praktykę. W przedstawionym kodzie [pyconnect.py](https://gist.github.com/jplochocki/1a7a206ae7e2b0f2243b1fa473b31003)
odbieranie pakietu `kdeconnect.share.request` odbywa się w funkcji
`device_connection_task()` (odpowiedzialnej po nawiązaniu połączenia, za
przetwarzanie pakietów przychodzących)

```python
async def device_connection_task(id_packet, remote_ip):
    # ...
        # receiving packets
        bssock = BufferedByteReceiveStream(ssock)
        async with anyio.create_task_group() as slave_group:
            # ...

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

                if pack['type'] == 'kdeconnect.share.request':
                    slave_group.start_soon(download_file_task, pack, remote_ip,
                                           ssl_context)
```

Przy pojawieniu się pakietu z plikiem - przechodzimy do funkcji
`download_file_task()` (wywoływanej jako oddzielne zadanie). Funkcja ta musi:
- Sprawdzić poprawność pakietu (pola `body.filename`, `payloadSize` i
`payloadTransferInfo.port` są wymagane). Linie `4` - `12`.
- Przygotować nazwę pliku docelowego (linie `14` - `21`).
- Nawiązać połączenie z [KDEConnect](https://play.google.com/store/apps/details?id=org.kde.kdeconnect_tp&hl=pl&gl=US)
na porcie wskazanym przez `payloadTransferInfo.port` (linie `25` - `27`).
- Pobrać plik (zakończenie połączenia nastąpi automatycznie po odebraniu
ostatnich danych). Linie `29` - `39`.

```python
async def download_file_task(pack, remote_ip, ssl_context):
    log.info(f'download_file_task() from {remote_ip}')

    if 'filename' not in pack['body']:
        log.error('download_file_task(): No filename property in pack.')
        return

    if 'payloadSize' not in pack or 'payloadTransferInfo' not in pack \
            or 'port' not in pack['payloadTransferInfo']:
        log.error(('download_file_task(): No payloadSize or '
                   'payloadTransferInfo property in pack.'))
        return

    # dest filename
    filename = os.path.join(os.path.expanduser('~'), pack['body']['filename'])
    i = 1
    while os.path.exists(filename):
        filename = os.path.splitext(pack['body']['filename'])
        filename = os.path.join(os.path.expanduser('~'),
                                f'{filename[0]}-{i}{filename[1]}')
        i += 1
    log.debug(f'download_file_task(): destination file: {filename}')

    # download
    async with await anyio.connect_tcp(
            remote_ip, pack['payloadTransferInfo']['port'],
            ssl_context=ssl_context) as sock:

        with open(filename, 'wb') as f:
            received = 0
            while received < pack['payloadSize']:
                data = await sock.receive()
                f.write(data)
                received += len(data)
                print((f'\r* download_file_task(): {pack["body"]["filename"]}'
                       f' - received bytes  +{len(data)} ({received} of'
                       f' {pack["payloadSize"]})'),
                      end='')
        print('')

    log.info('download_file_task(): download connection closed.')
```


Wysyłanie plików
----------------

Wysyłanie plików do [KDEConnect](https://play.google.com/store/apps/details?id=org.kde.kdeconnect_tp&hl=pl&gl=US)
przebiega bardzo podobnie do ich odbierania - też korzystamy z pakietu
`kdeconnect.share.request`, ale to my go układamy i wysyłamy. I my też musimy
(po określeniu, który port w zakresie  pomiędzy `1739` a `1764` jest wolny)
otworzyć serwer wysyłania pliku. Jeśli zostanie na nim nawiązane połączenie -
wysyłamy plik i kończymy działanie serwera.

W mojej implementacji [pyconnect.py](https://gist.github.com/jplochocki/1a7a206ae7e2b0f2243b1fa473b31003)
wykonywane było testowe wysyłanie pliku - uruchamiane jest nowe zadanie
(`slave_group.start_soon(test_upload_task, ssock, ssl_context)`),
które w dwie sekundy po starcie wysyła plik kodu `pyconnect.py` na urządzenie.

```python
async def test_upload_task(ssock, ssl_context):
    '''
    Test upload task - upload script itself
    '''
    await anyio.sleep(2)
    await upload_file(os.path.abspath(__file__), ssock, ssl_context)


async def upload_file(file_path, ssock, ssl_context):
    log.info(f'upload_file(): {file_path=}, {ssock=}, {ssl_context=}')

    if not os.path.exists(file_path):
        log.error(f'upload_file(): File not exists ({file_path})')
        return

    # start upload server
    file_size = os.path.getsize(file_path)
    server = None
    close_server_event = anyio.Event()

    async def handle_connection(sock_client):
        async with sock_client:
            with open(file_path, 'rb') as f:
                sent = 0
                while sent < file_size:
                    data = f.read(63 * 1024)
                    await sock_client.send(data)

                    sent += len(data)
                    print((f'\rupload_file() sent {sent} of {file_size} '
                           f'(+{len(data)})'), end='')
        print('')

        await server.aclose()
        close_server_event.set()

    transfer_port = 0
    for port in range(KDE_CONNECT_TRANSFER_MIN, KDE_CONNECT_TRANSFER_MAX + 1):
        try:
            server = TLSListener(await anyio.create_tcp_listener(
                local_port=port, local_host='0.0.0.0'),
                ssl_context=ssl_context, standard_compatible=False)
            log.info(f'upload_file(): - Selected port {port}')
            transfer_port = port

            break
        except OSError as e:
            if e.errno == 98:  # port already in use
                continue
            raise e

    # send ready packet
    pack = {
        'type': 'kdeconnect.share.request',
        'body': {
            'filename': os.path.basename(file_path),
            'open': False,
            'lastModified': int(os.path.getmtime(file_path)),
            'numberOfFiles': 1,
            'totalPayloadSize': file_size
        },
        'payloadSize': file_size,
        'payloadTransferInfo': {
            'port': transfer_port
        }
    }

    serve_forever = server.serve(handle_connection)
    await anyio.sleep(0.01)

    await ssock.send(prepare_to_send(pack))
    log.debug(f'upload_file(): invitation packet sent: {pack!r}')

    try:
        await serve_forever
    except anyio.ClosedResourceError:
        close_server_event.set()

    await close_server_event.wait()
    log.debug('upload_file(): transfer server closed')
```

---

W następnym poście zajmę się wysyłaniem i odbieraniem `SMS-ów`.
