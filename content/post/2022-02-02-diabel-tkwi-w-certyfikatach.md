---
title: "Diabeł tkwi w... certyfikatach"
date: 2022-02-02T21:57:22+01:00
tags: [Python, TLS, SSL, AnyIO]
draft: false
---

Ostatnio napotkałem na problem z certyfikatami samodzielnie podpisanymi, a dokładniej z pobieraniem certyfikatu klienta przy jego połączeniu z serwerem. Taki prosty przykład (zaczerpnięty z dokumentacji 
[AnyIO](https://anyio.readthedocs.io/en/stable/streams.html#tls-streams) - strona serwera:
<!--more-->

```python
import ssl

from anyio import create_tcp_listener, run
from anyio.streams.tls import TLSListener
from anyio.streams.tls import TLSAttribute


async def handle(client):
    async with client:
        name = await client.receive()
        await client.send(b'Hello, %s\n' % name)
        print('peer_certificate', client.extra(TLSAttribute.peer_certificate))
        print('peer_certificate_binary', client.extra(TLSAttribute.peer_certificate_binary))


async def main():
    # Create a context for the purpose of authenticating clients
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)

    # Load the server certificate and private key
    context.load_cert_chain(certfile='cert.pem', keyfile='key.pem')
    context.verify_mode = ssl.CERT_OPTIONAL  # ssl.CERT_REQUIRED
    # context.load_verify_locations(cafile='client_cert.pem')

    # Create the listener and start serving connections
    listener = TLSListener(await create_tcp_listener(local_port=1234), context)
    await listener.serve(handle)

run(main)
```

Aby mieć dostęp do **certyfikatu klienta** łączącego się z serwerem, musimy ustawić `context.verify_mode` na `ssl.CERT_OPTIONAL` lub `ssl.CERT_REQUIRED`
(wtedy też `TLSAttribute.peer_certificate` / `TLSAttribute.peer_certificate_binary` da nam w wyniku **certyfikat klienta**).
Ale `ssl.CERT_OPTIONAL` / `ssl.CERT_REQUIRED` wymuszają od razu sprawdzenie poprawności tego certyfikatu. Jeśli jest on podpisany przez znane dla systemu `CA`,
to nie mamy problemu. Schody zaczynają się, gdy mamy *self signed certificate* - czyli certyfikat samodzielnie podpisany. Nie możemy go pobrać w trakcie
[do_handshake](https://docs.python.org/3/library/ssl.html#ssl.SSLSocket.do_handshake) bez jego sprawdzania. A to sprawdzanie, z racji jego *self signed* da nam 
wyjątek:


> ssl.SSLCertVerificationError: [SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: self signed certificate (_ssl.c:1131)


A bez przejścia [do_handshake](https://docs.python.org/3/library/ssl.html#ssl.SSLSocket.do_handshake) funkcja 
[SSLSocket.getpeercert()](https://docs.python.org/3/library/ssl.html#ssl.SSLSocket.getpeercert) (z której wewnętrznie korzystają `TLSAttribute.peer_certificate`
i `TLSAttribute.peer_certificate_binary`) zwróci nam wyjątek [ValueError](https://docs.python.org/3/library/exceptions.html#ValueError)).

Po przeglądzie dokumentacji biblioteki [ssl](https://docs.python.org/3/library/ssl.html) okazało się, że nie ma tam mechanizmu, który w prosty sposób pozwalałby
na pobranie **certyfikatu klienta** za pierwszym razem bez jego weryfikacji, a sprawdzanie go przy następnych połączeniach (po dodaniu go jako zaufanego dzięki
funkcji [SSLContext.load_verify_locations](https://docs.python.org/3/library/ssl.html#ssl.SSLContext.load_verify_locations)).


Znalazłem jednak pewne rozwiązanie tego problemu. Biblioteka [ssl](https://docs.python.org/3/library/ssl.html) posiada nieudokumentowaną właściwość
`SSLContext._msg_callback` (fragment z kodu źródłowego [ssl.py](https://github.com/python/cpython/blob/83d544b9292870eb44f6fca37df0aa351c4ef83a/Lib/ssl.py#L643)):

```python
    @property
    def _msg_callback(self):
        """TLS message callback
        The message callback provides a debugging hook to analyze TLS
        connections. The callback is called for any TLS protocol message
        (header, handshake, alert, and more), but not for application data.
        Due to technical  limitations, the callback can't be used to filter
        traffic or to abort a connection. Any exception raised in the
        callback is delayed until the handshake, read, or write operation
        has been performed.
```

`Callback` ten wywoływany jest w trakcie interesującego nas procesu `handshake` z następującymi wartościami `content_type` i `msg_type`:

```python
    def msg_cb(conn, direction, version, content_type, msg_type, data):
        print(f'{content_type=}\t\t{msg_type=}')
    context._msg_callback = msg_cb
```

Wynik:

```
content_type=<_TLSContentType.HEADER: 256>		msg_type=<_TLSContentType.HANDSHAKE: 22>
content_type=<_TLSContentType.HANDSHAKE: 22>		msg_type=<_TLSMessageType.CLIENT_HELLO: 1>
content_type=<_TLSContentType.HEADER: 256>		msg_type=<_TLSContentType.HANDSHAKE: 22>
content_type=<_TLSContentType.HANDSHAKE: 22>		msg_type=<_TLSMessageType.SERVER_HELLO: 2>
content_type=<_TLSContentType.HEADER: 256>		msg_type=<_TLSContentType.CHANGE_CIPHER_SPEC: 20>
content_type=<_TLSContentType.CHANGE_CIPHER_SPEC: 20>		msg_type=<_TLSMessageType.CHANGE_CIPHER_SPEC: 257>
content_type=<_TLSContentType.HEADER: 256>		msg_type=<_TLSContentType.APPLICATION_DATA: 23>
content_type=<_TLSContentType.INNER_CONTENT_TYPE: 257>		msg_type=<_TLSMessageType.CERTIFICATE_STATUS: 22>
content_type=<_TLSContentType.HANDSHAKE: 22>		msg_type=<_TLSMessageType.ENCRYPTED_EXTENSIONS: 8>
content_type=<_TLSContentType.HEADER: 256>		msg_type=<_TLSContentType.APPLICATION_DATA: 23>
content_type=<_TLSContentType.INNER_CONTENT_TYPE: 257>		msg_type=<_TLSMessageType.CERTIFICATE_STATUS: 22>
content_type=<_TLSContentType.HANDSHAKE: 22>		msg_type=<_TLSMessageType.CERTIFICATE_REQUEST: 13>
content_type=<_TLSContentType.HEADER: 256>		msg_type=<_TLSContentType.APPLICATION_DATA: 23>
content_type=<_TLSContentType.INNER_CONTENT_TYPE: 257>		msg_type=<_TLSMessageType.CERTIFICATE_STATUS: 22>
content_type=<_TLSContentType.HANDSHAKE: 22>		msg_type=<_TLSMessageType.CERTIFICATE: 11>
content_type=<_TLSContentType.HEADER: 256>		msg_type=<_TLSContentType.APPLICATION_DATA: 23>
content_type=<_TLSContentType.INNER_CONTENT_TYPE: 257>		msg_type=<_TLSMessageType.CERTIFICATE_STATUS: 22>
content_type=<_TLSContentType.HANDSHAKE: 22>		msg_type=<_TLSMessageType.CERTIFICATE_VERIFY: 15>
content_type=<_TLSContentType.HEADER: 256>		msg_type=<_TLSContentType.APPLICATION_DATA: 23>
content_type=<_TLSContentType.INNER_CONTENT_TYPE: 257>		msg_type=<_TLSMessageType.CERTIFICATE_STATUS: 22>
content_type=<_TLSContentType.HANDSHAKE: 22>		msg_type=<_TLSMessageType.FINISHED: 20>
content_type=<_TLSContentType.HEADER: 256>		msg_type=<_TLSContentType.CHANGE_CIPHER_SPEC: 20>
content_type=<_TLSContentType.HEADER: 256>		msg_type=<_TLSContentType.APPLICATION_DATA: 23>
content_type=<_TLSContentType.INNER_CONTENT_TYPE: 257>		msg_type=<_TLSMessageType.CERTIFICATE_STATUS: 22>
content_type=<_TLSContentType.HANDSHAKE: 22>		msg_type=<_TLSMessageType.CERTIFICATE: 11>
content_type=<_TLSContentType.HEADER: 256>		msg_type=<_TLSContentType.APPLICATION_DATA: 23>
content_type=<_TLSContentType.INNER_CONTENT_TYPE: 257>		msg_type=<_TLSMessageType.CERTIFICATE_URL: 21>
content_type=<_TLSContentType.ALERT: 21>		msg_type=<_TLSAlertType.UNKNOWN_CA: 48>
```

Interesuje nas drugie wystąpienie `content_type ==_TLSContentType.HANDSHAKE` i `msg_type == _TLSMessageType.CERTIFICATE`. Wtedy przesyłany jest
**certyfikat klienta**, którego dane będą zawarte w `data`. Ale poprzedza je jeszcze nagłówek części pakietu, którego struktura (po uproszczeniu) wygląda
następująco:

```cpp
struct {
  uint8     msg_type;                   /* handshake type */
  uint24    length;                     /* bytes in message */
  uint24 / uint32    certificates_len;  /* uint24 przy TLSv1_2 i uint32 przyTLSv1_3 */
  uint24    first_cert_len;
  ... /* first certyficate bytes */
} Handshake_Certificate;
```

`msg_type` zawsze powinno mieć wartość `11` (pakiet `CERTIFICATE`). Trzy następne pola to wielkości danych
1) całego pakietu (`length`)
2) części z certyfikatami (`certificates_len` - w zależności czy mamy `TLSv1_2`, czy `TLSv1_3` - to pole ma różną długość!)
3) pierwszego certyfikatu (`first_cert_len`).

Po tym wstępie (`10` lub `11` bajtów) mamy właściwe dane binarne certyfikatu. Całość przetwarzamy za pomocą
[struct](https://docs.python.org/3/library/struct.html):

```python
    client_cert_request = False

    def msg_cb(conn, direction, version, content_type, msg_type, data):
        global client_cert_request
        if content_type != ssl._TLSContentType.HANDSHAKE:
            return

        if msg_type == ssl._TLSMessageType.CLIENT_HELLO:
            client_cert_request = False

        if msg_type == ssl._TLSMessageType.CERTIFICATE:
            if not client_cert_request:
                client_cert_request = True
                return

            handshake_type = struct.unpack('>B', data[0:1])[0]
            assert handshake_type == TLS_HANDSHAKE_TYPE_CERTIFICATE, \
                f'unknown packet type ({handshake_type})'

            if version == ssl.TLSVersion.TLSv1_3:
                cetrts_length = struct.unpack('>I', data[4:8])[0]
                certs_start = 8
            else:
                cetrts_length = struct.unpack('>I', b'\x00' + data[4:7])[0]
                certs_start = 7
            assert cetrts_length + certs_start <= len(data), \
                'not enought packet data'

            # interesuje nas tylko pierwszy certyfikat
            cert_len = struct.unpack(
                '>I', b'\x00' + data[certs_start:certs_start+3])[0]
            certs_start += 3
            cert_DER = data[certs_start:cert_len + certs_start]
            context.load_verify_locations(cadata=cert_DER)
            # cert_PEM = ssl.DER_cert_to_PEM_cert(cert_DER)
```

Zawartość `cert_DER` możemy na tym etapie wczytać funkcją 
[SSLContext.load_verify_locations](https://docs.python.org/3/library/ssl.html#ssl.SSLContext.load_verify_locations) do kontekstu. Będzie to skutkowało...
uznaniem tego **certyfikatu klienta** za prawidłowo podpisany. Dane te możemy też konwertować do tekstowego formatu `PEM` za pomocą funkcji
[DER_cert_to_PEM_cert](https://docs.python.org/3/library/ssl.html#ssl.DER_cert_to_PEM_cert) i zapisać je na dysku..

---
Przykłady do tego postu to: [server.py](https://gist.github.com/jplochocki/025892ec692bd90fd8ff170b03fd72d4) i
[client.py](https://gist.github.com/jplochocki/4031b4a5060be39ff969734fccc13b2a)
