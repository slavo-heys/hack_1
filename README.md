# Prosty przechwytywacz Wi‑Fi (libpcap + ncurses)

Ten repo zawiera przykład prostego narzędzia w C++ do etycznego testowania sieci Wi‑Fi:
- listuje tylko interfejsy Wi‑Fi i pokazuje nazwę urządzenia/sterownika,
- automatycznie (opcjonalnie) przełącza interfejs w tryb monitor,
- wykonuje live-skan beaconów i wyświetla dynamiczną tabelę w trybie `ncurses`,
- rozpoznaje podstawowe informacje z ramek 802.11 (SSID, BSSID, kanał, szyfrowanie, RSSI, vendor OUI),
- pozwala wybrać AP i zapisać przechwycone pakiety do pliku `.pcap`.
 - wykonuje live-skan beaconów i wyświetla dynamiczną tabelę w trybie `ncurses` (posortowaną po RSSI),
 - rozpoznaje podstawowe informacje z ramek 802.11 (SSID — kolumna do 40 znaków, BSSID, kanał, szyfrowanie, RSSI, vendor OUI),
 - umożliwia interaktywny wybór AP za pomocą kursora (strzałki) i potwierdzenie Enterem oraz zapis przechwyconych pakietów do pliku `.pcap`.

## Wymagania
- Linux z `libpcap` i `libncurses` (używane w przykładzie)
- kompilator `g++` (C++11+)
- uprawnienia root do ustawiania trybu monitor oraz przechwytywania pakietów

Na Debian/Ubuntu/Kali zainstaluj:

```bash
sudo apt update
sudo apt install -y libpcap-dev libncurses-dev build-essential
```

## Kompilacja

W katalogu repo uruchom:

```bash
g++ start.cpp -lpcap -lncurses -o start
```

## Uruchomienie i opcje

Podstawowe uruchomienie (zalecane z `sudo`):

```bash
sudo ./start
```

Dostępne flagi CLI:

- `--no-monitor` — nie próbuj ustawiać interfejsu w tryb monitor (przydatne gdy nie chcesz zmieniać stanu urządzenia).
- `--force-monitor` — spróbuj wymusić monitor (program będzie sygnalizował próbę nawet jeśli niezalecane).
- `--oui-db <file>` — załaduj plik z mapą OUI→vendor (np. pobrany plik IEEE lub inny prosty format).
- `--json <file>` — zapisz metadane znalezionych AP (SSID, BSSID, CH, ENC, RSSI, vendor) w pliku JSON po zakończeniu przechwytywania.
- `--filter-enc <enc>` — podczas skanowania pokaż tylko AP zawierające podany tekst w polu szyfrowania (np. `WPA2`).
- `-h, --help` — wyświetl pomoc i zakończ.

Przykłady:

- automatyczny monitor + live UI:
```bash
sudo ./start --force-monitor
```

- bez zmiany trybu interfejsu:
```bash
./start --no-monitor
```

- użycie pliku OUI i zapis JSON z metadanymi:
```bash
sudo ./start --oui-db /path/to/oui.txt --json results.json
```

## Interakcja (UI)
- Po uruchomieniu program wyświetla tabelę interfejsów Wi‑Fi (kolumny: `idx | INTERFEJS | DEVICE | OPIS`).
- Wybierz numer interfejsu, program spróbuje ustawić tryb monitor (chyba że użyto `--no-monitor`).
- Działa live-skan beaconów w trybie `ncurses`. Odświeżanie co ~300 ms.
 - Działa live-skan beaconów w trybie `ncurses`. Odświeżanie co ~300 ms. Lista jest na żywo sortowana według siły sygnału (RSSI), na górze widoczne są najsilniejsze AP.
 - Interaktywny wybór AP: użyj klawiszy `↑` / `↓` aby poruszać kursorem po liście i naciśnij `Enter`, aby wybrać AP. Alternatywnie możesz zakończyć skan `Ctrl+C` lub `q`, po czym program poprosi o wybór indeksem.
 - Po wyborze AP wpisz nazwę pliku do zapisu (domyślnie `capture.pcap`) — program zapisuje surowe pakiety do wskazanego pliku.

## Uwagi i ograniczenia
- Tryb monitor i działanie filtrów BPF wymaga, aby interfejs zwracał DLT 802.11 (radiotap). Na niektórych sterownikach lub platformach ustawienie filtra może zwracać błąd "Network is down" lub podobny — w takim wypadku sprawdź czy interfejs rzeczywiście działa w trybie monitor lub użyj `--no-monitor`.
- Parser RSN/802.11 zaimplementowany jest w sposób praktyczny i uproszczony (wyciąga pierwszy pairwise cipher i oznacza podstawowe typy szyfrowania). Można go rozszerzyć o pełne dekodowanie IE.
- Baza OUI: program zawiera prosty loader `--oui-db` i podstawową mapę; dla dokładnych vendorów warto pobrać oficjalny plik IEEE OUI i podać go flagą `--oui-db`.

## Bezpieczeństwo i etyka
To narzędzie jest przykładem edukacyjnym. Używaj go wyłącznie do testów sieci, do których masz uprawnienia (twoje własne urządzenia, laboratoria testowe, zgoda właściciela). Nie używaj do nieautoryzowanego przechwytywania ruchu ani atakowania cudzych sieci.

## Dalsze rozszerzenia (możesz poprosić o implementację)
- Pełne parsowanie RSN/WPA (lista cipherów, AKM suites)
- Pełna baza OUI z automatycznym pobieraniem i aktualizacją
 - Eksport PCAP + metadanych do jednego archiwum
 - Rozszerzone filtry na żywo w UI

## Przykładowe zrzuty ekranu i wyjście
Poniżej znajduje się przykładowe, tekstowe wyjście programu (fragment), które możesz umieścić jako zrzut ekranu w dokumentacji. Zamiast obrazków zamieszczamy też prosty opis jak wykonać zrzut ekranu terminala.

Przykładowe live (ncurses) — fragment tabeli:

```
Live:  wykryte sieci (Ctrl+C aby zakończyć)
idx | SSID                                     | BSSID                   |  CH | ENC                  | RSSI | VENDOR     
-----------------------------------------------------------------------------------------------
	0  | MyHomeNetwork                             | 12:34:56:78:9a:bc       |   11| WPA2-CCMP            |  -45 | 12:34:56   
	1  | NeighborNet                               | ab:cd:ef:01:23:45       |    6| WPA2-CCMP            |  -72 | ab:cd:ef   
```

Przykładowa tabela po zakończeniu skanowania (statyczna):

```
idx | SSID                                     | BSSID                   |  CH | ENC                  | RSSI | VENDOR     
------------------------------------------------------------------------------------------------
	0  | MyHomeNetwork                             | 12:34:56:78:9a:bc       |   11| WPA2-CCMP            |  -45 | 12:34:56   
	1  | NeighborNet                               | ab:cd:ef:01:23:45       |    6| WPA2-CCMP            |  -72 | ab:cd:ef   
```

Jak wykonać zrzut ekranu terminala (szybki sposób):

- Opcja `scrot` (prosty screenshot całego ekranu):

```bash
sudo apt install scrot       # jeśli nie masz
scrot wifi-live.png          # zapisze zrzut ekranu do wifi-live.png
```

- Opcja `import` (z pakietu ImageMagick) pozwala wybrać obszar okna terminala:

```bash
sudo apt install imagemagick
import wifi-live.png         # potem kliknij i zaznacz obszar terminala
```

Po wykonaniu zdjęć możesz skopiować pliki PNG do repo (np. `docs/`) i dodać je do README korzystając z markdown:

```markdown
![Live scan](/docs/wifi-live.png)
![Tabela po skanie](/docs/wifi-table.png)
```

Jeśli chcesz, mogę:
- przygotować przykładowe obrazy (placeholdery) i dodać je do repo,
- lub dodać skrypt `capture_screens.sh`, który automatycznie uruchamia program i wykonuje zrzut ekranu (wymaga narzędzi `scrot`/`import`).
- Eksport PCAP + metadanych do jednego archiwum

## Kontakt / Wkład
Jeśli chcesz, żebym dodał któreś z rozszerzeń (np. pełne parsowanie RSN, rozszerzoną bazę OUI, lub ulepszenia UI), napisz które — wprowadzę to i przygotuję testy.

---
Plik `start.cpp` znajduje się w tym repo; uruchomienie i testowanie wymaga uprawnień oraz kompatybilnego adaptera Wi‑Fi.
