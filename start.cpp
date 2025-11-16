/*
  Przykładowy program w C++ z polskimi komentarzami, który demonstruje
  podstawowe kroki opisane w oryginalnym komentarzu:

  - listowanie interfejsów sieciowych przy pomocy libpcap
  - wybranie interfejsu przez użytkownika
  - (opcjonalne) przełączenie interfejsu w tryb monitor (wywołania systemowe)
  - przechwytywanie pakietów i zapis do pliku .pcap
  - obsługa przerwania (Ctrl+C) z bezpiecznym zakończeniem i przywróceniem

  Uwaga: pełne skanowanie Wi‑Fi (parsowanie beaconów, dekodowanie szyfrowania,
  wyświetlanie kanału itd.) wymaga dodatkowego kodu (analizy nagłówków 802.11)
  oraz uprawnień roota. Ten przykład pokazuje prostą, bezpieczną bazę,
  łatwą do rozszerzenia.

  Kompilacja:
    g++ start.cpp -lpcap -o start

  Program nie używa ncurses w tej wersji, żeby kod był czytelny — można
  dodać interfejs tekstowy później.
*/

#include <pcap.h>
#include <csignal>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <vector>
#include <string>
#include <map>
#include <cstdint>
#include <ctime>
#include <sys/stat.h>
#include <fstream>
#include <sstream>
#include <unistd.h>
#include <iomanip>
#include <limits.h>
#include <ncurses.h>
#include <thread>
#include <chrono>
#include <unordered_map>
#include <mutex>
#include <algorithm>
#include <arpa/inet.h>

// Globalne wskaźniki używane przez signal handler i callback
static pcap_t *global_handle = nullptr;
static pcap_dumper_t *global_dumper = nullptr;
static bool monitor_enabled = false;
static std::string selected_iface;
// flaga ustawiana przez handler sygnału gdy użytkownik naciśnie Ctrl+C
static volatile sig_atomic_t stop_flag = 0;

// Kody kolorów ANSI (globalnie dostępne)
static const char *C_RESET = "\x1b[0m";
static const char *C_BOLD = "\x1b[1m";
static const char *C_RED = "\x1b[31m";
static const char *C_YELLOW = "\x1b[33m";
static const char *C_GREEN = "\x1b[32m";
static const char *C_CYAN = "\x1b[36m";
static const char *C_BLUE = "\x1b[34m";

// Handler sygnału (np. Ctrl+C). Zatrzymuje pcap_loop bezpośrednio.
void handle_sigint(int sig) {
    // ustaw flaga — pętle sprawdzają ją i kończą się uporządkowanie
    stop_flag = 1;
    if (global_handle) {
        // przerwij ewentualną pcap_loop (przechwytywanie pakietów)
        pcap_breakloop(global_handle);
    }
}

// Callback wywoływany dla każdego przechwyconego pakietu.
// Argument 'user' to wskaźnik, który przekażemy (tu: pcap_dumper_t*).
void packet_handler(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes) {
    pcap_dumper_t *dumper = reinterpret_cast<pcap_dumper_t*>(user);
    if (dumper) {
        // Zapisujemy surowy pakiet do pliku .pcap
        pcap_dump(reinterpret_cast<u_char*>(dumper), h, bytes);
    }
}

int main(int argc, char **argv) {
    char errbuf[PCAP_ERRBUF_SIZE];

    // Parsowanie prostych flags CLI
    bool opt_no_monitor = false;
    bool opt_force_monitor = false;
    std::string oui_db_file;
    std::string json_out_file;
    std::string filter_enc;
    int capture_time = 0; // seconds; 0 = fallback to eapol_threshold
    int eapol_threshold = 3; // ile ramek EAPOL powoduje zakończenie, gdy -t nie ustawione
    std::string out_dir; // katalog wyjściowy
    std::string auto_name_format = "capture_%Y%m%d_%H%M%S.pcap"; // format nazwy zgodny ze strftime
    int rotate_time = 0; // seconds; 0 = no rotation
    bool eapol_dump_enabled = false;
    std::string eapol_dump_file; // optional path
    std::string pmkid_out_arg; // optional override for pmkid output
    std::string hccapx_out_file; // experimental binary/text hccapx output
    std::string handshake_out_dir; // directory to save extracted handshake pcaps/text
    for (int ai = 1; ai < argc; ++ai) {
        std::string a = argv[ai];
        if (a == "--no-monitor") opt_no_monitor = true;
        else if (a == "--force-monitor") opt_force_monitor = true;
        else if (a == "--oui-db" && ai+1 < argc) { oui_db_file = argv[++ai]; }
        else if (a == "--json" && ai+1 < argc) { json_out_file = argv[++ai]; }
        else if (a == "--filter-enc" && ai+1 < argc) { filter_enc = argv[++ai]; }
        else if ((a == "-t" || a == "--time") && ai+1 < argc) { capture_time = std::atoi(argv[++ai]); if (capture_time < 0) capture_time = 0; }
        else if ((a == "--eapol-count") && ai+1 < argc) { eapol_threshold = std::atoi(argv[++ai]); if (eapol_threshold < 1) eapol_threshold = 1; }
        else if (a == "--out-dir" && ai+1 < argc) { out_dir = argv[++ai]; }
        else if (a == "--auto-name-format" && ai+1 < argc) { auto_name_format = argv[++ai]; }
        else if (a == "--rotate-time" && ai+1 < argc) { rotate_time = std::atoi(argv[++ai]); if (rotate_time < 1) rotate_time = 0; }
        else if (a == "--eapol-dump") { eapol_dump_enabled = true; }
        else if (a == "--eapol-dump-file" && ai+1 < argc) { eapol_dump_enabled = true; eapol_dump_file = argv[++ai]; }
        else if (a == "--pmkid-out" && ai+1 < argc) { pmkid_out_arg = argv[++ai]; }
        else if (a == "--hccapx-out" && ai+1 < argc) { hccapx_out_file = argv[++ai]; }
        else if (a == "--handshake-out-dir" && ai+1 < argc) { handshake_out_dir = argv[++ai]; }
        else if (a == "-h" || a == "--help") {
            std::cout << "Użycie: " << argv[0] << " [--no-monitor] [--force-monitor] [--oui-db <file>] [--json <file>] [--filter-enc <enc>] [-t <s>]\n";
            std::cout << "  --no-monitor     : nie próbuj ustawiać trybu monitor\n";
            std::cout << "  --force-monitor  : wymuś monitor (spróbuj, nawet jeśli niezalecane)\n";
            std::cout << "  --oui-db <file>  : załaduj bazę OUI (format 'xx:xx:xx Vendor' lub IEEE oui.txt)\n";
            std::cout << "  --json <file>    : zapisz metadane znalezionych AP do pliku JSON po przechwytywaniu\n";
            std::cout << "  --filter-enc <e> : podczas skanowania pokazuj tylko AP zawierające <e> w typie szyfrowania\n";
            std::cout << "  -t, --time <s>   : podczas przechwytywania zakończ po <s> sekundach; jeśli brak, zatrzymaj po wykryciu N ramek EAPOL (patrz --eapol-count)\n";
            std::cout << "  --eapol-count <n>: liczba ramek EAPOL potrzebna do zakończenia gdy -t nie ustawione (domyślnie 3)\n";
            std::cout << "  --out-dir <dir>  : katalog do zapisu plików pcap (domyślnie bieżący katalog)\n";
            std::cout << "  --auto-name-format <fmt> : format nazwy pliku zgodny ze strftime (domyślnie 'capture_%Y%m%d_%H%M%S.pcap')\n";
            std::cout << "  --rotate-time <s>: automatyczna rotacja pliku pcap co <s> sekund (0 = wyłączona)\n";
            std::cout << "  --eapol-dump     : zapisz wykryte ramki EAPOL do oddzielnego pliku pcap\n";
            std::cout << "  --eapol-dump-file <file> : użyj konkretnej ścieżki pliku do dump EAPOL\n";
            return 0;
        }
    }

    std::cout << "-- Prosty przechwytywacz pakietów (libpcap) --\n";

    // 1) Pobierz listę dostępnych interfejsów
    pcap_if_t *alldevs;
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        std::cerr << "Błąd pcap_findalldevs: " << errbuf << "\n";
        return 1;
    }

    // 2) Wyświetl interfejsy w tabeli – tylko interfejsy Wi‑Fi
    struct IfaceInfo { std::string name; std::string desc; std::string devname; };
    std::vector<IfaceInfo> wifi_ifaces;

    auto is_wireless = [&](const std::string &ifname)->bool{
        // 1) Sprawdź /sys/class/net/<if>/wireless
        std::string path = std::string("/sys/class/net/") + ifname + "/wireless";
        struct stat st;
        if (stat(path.c_str(), &st) == 0) return true;

        // 2) Sprawdź /proc/net/wireless (zawiera listę interfejsów jeśli są wireless)
        std::ifstream f("/proc/net/wireless");
        if (!f) return false;
        std::string line;
        while (std::getline(f, line)) {
            // linie zwykle zaczynają się od: "Inter-| sta ..." lub "  wlan0:"
            // Szukamy nazwy interfejsu followed by ':'
            size_t pos = line.find(ifname + ":");
            if (pos != std::string::npos) return true;
        }
        return false;
    };

    // Pobierz nazwę urządzenia (np. driver lub product) dla interfejsu
    auto get_device_name = [&](const std::string &ifname)->std::string{
        std::string uevent = std::string("/sys/class/net/") + ifname + "/device/uevent";
        std::ifstream f(uevent);
        if (f) {
            std::string line;
            while (std::getline(f, line)) {
                if (line.rfind("DRIVER=", 0) == 0) return line.substr(7);
                if (line.rfind("PRODUCT=", 0) == 0) return line.substr(8);
            }
        }
        // Spróbuj odczytać powiązanie driver
        std::string drvpath = std::string("/sys/class/net/") + ifname + "/device/driver";
        char buf[PATH_MAX];
        ssize_t len = readlink(drvpath.c_str(), buf, sizeof(buf)-1);
        if (len > 0) {
            buf[len] = '\0';
            std::string s = buf;
            // basename
            size_t p = s.find_last_of('/');
            if (p != std::string::npos) return s.substr(p+1);
            return s;
        }
        return std::string("");
    };

    int idx = 0;
    for (pcap_if_t *d = alldevs; d; d = d->next) {
        std::string name = d->name ? d->name : "(brak nazwy)";
        if (!is_wireless(name)) continue; // pomiń interfejsy nie‑WiFi
        IfaceInfo info;
        info.name = name;
        info.desc = d->description ? d->description : "";
        info.devname = get_device_name(name);
        wifi_ifaces.push_back(info);
    }

    if (wifi_ifaces.empty()) {
        std::cerr << "Nie znaleziono interfejsów Wi‑Fi. Upewnij się, że masz adapter Wi‑Fi lub uruchom program z uprawnieniami.", std::cout << "\n";
        pcap_freealldevs(alldevs);
        return 1;
    }

    // Wyświetl w ładnej tabeli (dodajemy kolumnę 'DEVICE')
    std::cout << "idx | INTERFEJS       | DEVICE          | OPIS\n";
    std::cout << "-------------------------------------------------------------\n";
    for (size_t i = 0; i < wifi_ifaces.size(); ++i) {
        char buf[512];
        std::snprintf(buf, sizeof(buf), "%3zu | %-15s | %-14s | %s",
            i, wifi_ifaces[i].name.c_str(), wifi_ifaces[i].devname.c_str(), wifi_ifaces[i].desc.c_str());
        std::cout << buf << "\n";
    }

    int choice = 0;
    std::cout << "\nWybierz interfejs Wi‑Fi (numer): ";
    std::cin >> choice;
    if (choice < 0 || choice >= static_cast<int>(wifi_ifaces.size())) {
        std::cerr << "Nieprawidłowy wybór.\n";
        pcap_freealldevs(alldevs);
        return 1;
    }

    selected_iface = wifi_ifaces[choice].name;
    std::cout << "Wybrano: " << selected_iface << "\n";

    // 3) Automatyczne próby przełączenia interfejsu w tryb monitor (wymaga sudo)
    if (!opt_no_monitor) {
        std::cout << C_BOLD << "Automatyczne przełączenie interfejsu w tryb monitor (wymaga sudo)..." << C_RESET << "\n";
        std::string cmd_down = "sudo ip link set " + selected_iface + " down";
        std::string cmd_mon = "sudo iw dev " + selected_iface + " set type monitor";
        std::string cmd_up = "sudo ip link set " + selected_iface + " up";

        std::cout << "Wykonywanie: " << cmd_down << "\n";
        int r1 = system(cmd_down.c_str());
        std::cout << "Wykonywanie: " << cmd_mon << "\n";
        int r = system(cmd_mon.c_str());
        if (r != 0) {
            std::string warn = opt_force_monitor ? std::string("(force) Nie udało się ustawić monitor, kontynuuję...") : std::string("Nie udało się ustawić monitor. Kontynuuję bez trybu monitor.");
            std::cerr << C_YELLOW << "UWAGA: " << warn << "\n" << C_RESET;
            // postaraj się przywrócić interfejs
            std::cout << "Wykonywanie: " << cmd_up << "\n";
            system(cmd_up.c_str());
        } else {
            monitor_enabled = true;
            std::cout << C_GREEN << "Przełączono w tryb monitor." << C_RESET << "\n";
            std::cout << "Wykonywanie: " << cmd_up << "\n";
            system(cmd_up.c_str());
            // daj krótką chwilę na stabilizację
            sleep(1);
        }
    } else {
        std::cout << C_YELLOW << "Opcja --no-monitor aktywna: pomijam ustawianie trybu monitor." << C_RESET << "\n";
    }

    // 4) Otwórz interfejs do przechwytywania (użyjemy go najpierw do skanowania beaconów)
    int snaplen = 65535; // maksymalny rozmiar pakietu do przechwycenia
    int promisc = 1;     // włącz tryb promisc (odbiór wszystkich pakietów)
    int to_ms = 1000;    // timeout w ms

    global_handle = pcap_open_live(selected_iface.c_str(), snaplen, promisc, to_ms, errbuf);
    if (!global_handle) {
        std::cerr << "pcap_open_live nie powiodło się: " << errbuf << "\n";
        pcap_freealldevs(alldevs);
        return 1;
    }

    // Zarejestruj handler Ctrl+C przed skanowaniem
    std::signal(SIGINT, handle_sigint);

    // Pomocnicze struktury do zbierania informacji o AP
    struct APInfo {
        std::string ssid;
        std::string bssid;
        int channel = 0;
        int8_t max_rssi = -128;
        std::string enc = "OPEN";
        std::string vendor = ""; // vendor z OUI
    };

    // Mapujemy BSSID -> APInfo
    std::map<std::string, APInfo> aps;
    std::mutex aps_mtx;

    // Prosty słownik OUI -> vendor (można rozszerzyć lub załadować z pliku)
    std::unordered_map<std::string,std::string> oui_map = {
        {"00:0f:ac", "IEEE 802.11i"},
        {"00:50:f2", "Microsoft (WPA)"}
    };

    auto normalize_oui = [&](const std::string &s)->std::string{
        // oczekujemy formatu xx:xx:xx lub xxxxxx
        std::string t;
        for (char c: s) {
            if (isxdigit((unsigned char)c)) t.push_back(tolower(c));
        }
        if (t.size() < 6) return std::string("");
        // wstaw ':' po każdym bajcie
        std::string out;
        for (size_t i=0;i<6;i+=2) {
            out += t.substr(i,2);
            if (i < 4) out.push_back(':');
        }
        return out;
    };

    auto load_oui_db = [&](const std::string &path){
        std::ifstream f(path);
        if (!f) return;
        std::string line;
        while (std::getline(f, line)) {
            // próbuj wyciągnąć hex i vendor
            // akceptujemy formaty: "XX-XX-XX   (hex)   Vendor" lub "xx:xx:xx Vendor"
            std::string hex;
            std::string name;
            // znajdź pierwszy segment zawierający 6 hex
            for (size_t i=0; i+6<=line.size(); ++i) {
                bool ok = true; int cnt=0;
                for (size_t j=0;i+j<line.size() && cnt<6 && j<12; ++j) {
                    char c = line[i+j];
                    if (isxdigit((unsigned char)c)) { cnt++; }
                    else if (c==' '||c=='\t'||c==':'||c=='-') continue;
                    else { ok=false; break; }
                }
                if (ok && cnt==6) { hex = line.substr(i,12); break; }
            }
            if (hex.empty()) continue;
            // normalize and vendor = rest of line after hex
            std::string norm = normalize_oui(hex);
            size_t pos = line.find("\t");
            if (pos==std::string::npos) pos = line.find("  ");
            if (pos!=std::string::npos) name = line.substr(pos+1);
            if (name.empty()) {
                // fallback: everything after hex occurrence
                size_t hpos = line.find(hex);
                if (hpos!=std::string::npos) name = line.substr(hpos+hex.size());
            }
            // trim
            while (!name.empty() && isspace((unsigned char)name.front())) name.erase(name.begin());
            while (!name.empty() && isspace((unsigned char)name.back())) name.pop_back();
            if (!norm.empty() && !name.empty()) oui_map[norm] = name;
        }
    };

    auto lookup_oui = [&](const std::string &bssid)->std::string{
        if (bssid.size() < 8) return "";
        std::string prefix = bssid.substr(0,8);
        auto it = oui_map.find(prefix);
        if (it != oui_map.end()) return it->second;
        return prefix; // domyślnie zwróć prefix hex
    };

    if (!oui_db_file.empty()) load_oui_db(oui_db_file);

    // Sprawdź typ link-layer — jeśli nie obsługuje 802.11, nie ustawiaj filtra beacon
    int dlt = pcap_datalink(global_handle);
    bool supports_80211 = (dlt == DLT_IEEE802_11_RADIO) || (dlt == DLT_IEEE802_11);
    struct bpf_program fp;
    const char *beacon_filter = "type mgt subtype beacon";
    if (!supports_80211) {
        std::cerr << C_YELLOW << "Uwaga: interfejs nie zwraca DLT_802.11, filtr beacon nie zostanie ustawiony.\n" << C_RESET;
    } else {
        if (pcap_compile(global_handle, &fp, beacon_filter, 1, PCAP_NETMASK_UNKNOWN) == -1) {
            std::cerr << "pcap_compile (beacon filter) failed: " << pcap_geterr(global_handle) << "\n";
        } else {
            if (pcap_setfilter(global_handle, &fp) == -1) {
                std::cerr << "pcap_setfilter (beacon) failed: " << pcap_geterr(global_handle) << "\n";
            }
            pcap_freecode(&fp);
        }
    }

    // Funkcja pomocnicza do formatowania MAC jako stringa
    auto mac_to_str = [](const u_char *mac)->std::string{
        char buf[64];
        std::sprintf(buf, "%02x:%02x:%02x:%02x:%02x:%02x",
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
        return std::string(buf);
    };

    // Prosty parser radiotap aby spróbować wydobyć dBm Antenna Signal (RSSI).
    // Radiotap ma złożony format; tu implementujemy minimalny walker zgodny
    // z kolejnością pól radiotap i obsługą rozszerzeń 'present'. Nie jest to
    // pełna implementacja, ale działa dla większości sterowników.
    auto extract_rssi_from_radiotap = [](const u_char *data, int caplen)->int8_t{
        if (caplen < 8) return -128;
        // wersja(1), pad(1), len(2), present(4...)
        uint16_t it_len = *(const uint16_t*)(data + 2);
        if (it_len > (uint16_t)caplen) return -128;

        // Odczytaj wszystkie pola 'present'
        std::vector<uint32_t> presents;
        const u_char *p = data + 4;
        int offset = 0;
        while (true) {
            if (4 + offset + 4 > caplen) break;
            uint32_t word = *(const uint32_t*)(p + offset);
            presents.push_back(word);
            offset += 4;
            if ((word & 0x80000000) == 0) break; // brak kolejnego rozszerzenia
        }

        // Zacznij od pola po nagłówku (który ma 8 bajtów + len(presents)*4)
        int field_offset = 8 + (int)presents.size() * 4;

        // Lista rozmiarów i wyrównań dla pierwszych pól radiotap (kolejność specyfikacji)
        const int align[] = {8,1,1,2,2,1,1,2,2,2,1,1,1,2};
        const int size[]  = {8,1,1,4,2,1,1,2,2,2,1,1,1,2};
        // indeks pola: 0 TSFT,1 Flags,2 Rate,3 Channel,4 FHSS,5 dBm Antenna Signal

        int bit_index = 0;
        for (size_t w = 0; w < presents.size(); ++w) {
            uint32_t word = presents[w];
            for (int b = 0; b < 32; ++b, ++bit_index) {
                if (word & (1u << b)) {
                    // Sprawdź czy mamy size/align zdefiniowane
                    int fsize = 0, falign = 1;
                    if (bit_index < (int)(sizeof(size)/sizeof(size[0]))) {
                        fsize = size[bit_index];
                        falign = align[bit_index];
                    } else {
                        // pola poza zasięgiem naszej tablicy: pomiń (brak pewności co do rozmiaru)
                        fsize = 0; falign = 1;
                    }
                    if (fsize > 0) {
                        // wyrównaj offset
                        int pad = (falign - (field_offset % falign)) % falign;
                        field_offset += pad;
                        // sprawdź zakres
                        if (field_offset + fsize > caplen) return -128;
                        if (bit_index == 5) {
                            // dBm Antenna Signal: 1 bajt signed
                            int8_t rssi = *(const int8_t*)(data + field_offset);
                            return rssi;
                        }
                        field_offset += fsize;
                    }
                }
            }
        }
        return -128;
    };

    // Parser beaconów – zbiera SSID, channel, encryption, RSSI, BSSID
    auto process_beacon = [&](const struct pcap_pkthdr *h, const u_char *packet) {
        int caplen = h->caplen;
        if (caplen < 36) return; // zbyt mały

        // Odczytaj długość nagłówka radiotap
        if (caplen < 4) return;
        uint16_t rt_len = *(const uint16_t*)(packet + 2);
        if (rt_len >= (uint16_t)caplen) return;

        const u_char *dot11 = packet + rt_len;
        int dot11_len = caplen - rt_len;
        if (dot11_len < 36) return; // min 24 (hdr) + 12 (fixed)

        const u_char *bssid_ptr = dot11 + 16; // addr3
        std::string bssid = mac_to_str(bssid_ptr);

        // Spróbuj uzyskać RSSI z radiotap
        int8_t rssi = extract_rssi_from_radiotap(packet, caplen);

        // Odczytaj capability info, by sprawdzić bit 'privacy'
        const u_char *fixed = dot11 + 24; // timestamp(8), beacon interval(2), capability(2) -> capability at +10
        if (dot11_len < 36) return;
        uint16_t capability = 0;
        capability = *(const uint16_t*)(fixed + 10);

        // Przechodzimy przez tagi
        const u_char *tags = fixed + 12; // po fixed params
        int tags_len = dot11_len - 24 - 12;
        std::string ssid = "<hidden>";
        int channel = 0;
        bool has_rsn = false;
        bool has_wpa = false;
        std::string enc = "OPEN";

        int idx = 0;
        while (idx + 2 <= tags_len) {
            uint8_t id = tags[idx];
            uint8_t len = tags[idx+1];
            if (idx + 2 + len > tags_len) break;
            const u_char *val = tags + idx + 2;
            if (id == 0) { // SSID
                // jeśli SSID ukryty, oznaczamy to czytelnym tokenem
                if (len == 0) ssid = "<hidden>"; else ssid = std::string((const char*)val, len);
            } else if (id == 3 && len >= 1) { // DS Parameter set - channel
                channel = val[0];
                } else if (id == 48) { // RSN -> WPA2
                    has_rsn = true;
                    // prosty parser RSN: wersja(2), group cipher(4), pairwise count(2), pairwise list
                    if (len >= 8) {
                        const u_char *p = val;
                        // group cipher OUI+type (4 bytes)
                        const u_char *group = p + 2;
                        // pairwise count at offset 6
                        uint16_t pair_cnt = *(const uint16_t*)(p + 6);
                        std::string cipher = "";
                        if (pair_cnt > 0 && len >= (int)(8 + 4*pair_cnt)) {
                            const u_char *pair0 = p + 8; // first pairwise
                            // pair0[0..2] = OUI, pair0[3] = type
                            char obuf[16];
                            std::snprintf(obuf, sizeof(obuf), "%02x:%02x:%02x", pair0[0], pair0[1], pair0[2]);
                            std::string oui = obuf;
                            int ctype = pair0[3];
                            std::string cname = "";
                            // rozpoznaj popularne kombinacje
                            if ((oui == "00:0f:ac" && ctype == 4) || (oui == "00:50:f2" && ctype == 4)) cname = "CCMP";
                            else if ((oui == "00:0f:ac" && ctype == 2) || (oui == "00:50:f2" && ctype == 2)) cname = "TKIP";
                            else if (ctype == 1) cname = "WEP";
                            if (!cname.empty()) cipher = std::string("WPA2-") + cname;
                        }
                        if (!cipher.empty()) enc = cipher;
                    }
            } else if (id == 221 && len >= 4) {
                // Vendor specific: possible WPA OUI
                // WPA OUI: 00:50:f2, type 1
                if (val[0] == 0x00 && val[1] == 0x50 && val[2] == 0xf2 && val[3] == 0x01) {
                    has_wpa = true;
                }
            }
            idx += 2 + len;
        }

        if (enc == "OPEN") {
            if (has_rsn) enc = "WPA2";
            else if (has_wpa) enc = "WPA";
            else if (capability & 0x0010) enc = "WEP/Protected";
        }

        std::lock_guard<std::mutex> lk(aps_mtx);
        auto it = aps.find(bssid);
        if (it == aps.end()) {
            APInfo a;
            a.ssid = ssid;
            a.bssid = bssid;
            a.channel = channel;
            a.enc = enc;
            a.max_rssi = rssi;
            a.vendor = lookup_oui(bssid);
            aps[bssid] = a;
        } else {
            // Zaktualizuj wartość RSSI jeśli większa
            if (rssi > it->second.max_rssi) it->second.max_rssi = rssi;
            if (!ssid.empty() && it->second.ssid != ssid) it->second.ssid = ssid;
            if (channel != 0) it->second.channel = channel;
        }
    };

    // Skanuj beacony w pętli dopóki użytkownik nie naciśnie Ctrl+C
    // Kolumny szerokości (dostosowalne)
    const int COL_SSID = 40;
    const int COL_BSSID = 23;
    const int COL_CH = 4;
    const int COL_ENC = 20;
    const int COL_RSSI = 5;
    const int COL_VENDOR = 12;

    // Uruchom ncurses aby wyświetlać live tabelę AP
    initscr();
    cbreak();
    noecho();
    nodelay(stdscr, TRUE); // getch() nie blokuje
    keypad(stdscr, TRUE);

    std::cout << "Skanuję sieci Wi‑Fi (live). Naciśnij Ctrl+C, aby zakończyć skanowanie i wybrać sieć...\n";
    int row_off = 2;
    int cursor = 0; // indeks w posortowanej liście
    int selected_ap = -1; // jeśli użytkownik wybierze Enterem
    while (!stop_flag) {
        struct pcap_pkthdr *hdr;
        const u_char *pkt_data;
        int res = pcap_next_ex(global_handle, &hdr, &pkt_data);
        if (res == 1) {
            process_beacon(hdr, pkt_data);
        } else if (res == -1) {
            // wyświetl błąd w ncurses
            mvprintw(0,0, "Błąd pcap_next_ex: %s", pcap_geterr(global_handle));
            break;
        }

        // odśwież ekran co 300ms
        // Przygotuj snapshot i posortuj po RSSI malejąco
        std::vector<APInfo> snap;
        {
            std::lock_guard<std::mutex> lk(aps_mtx);
            for (auto &kv : aps) snap.push_back(kv.second);
        }
        std::sort(snap.begin(), snap.end(), [](const APInfo &a, const APInfo &b){ return a.max_rssi > b.max_rssi; });

        // drukuj nagłówek (używamy ncurses, nie ANSI escape)
        erase();
        mvprintw(0,0, "Live:  wykryte sieci (Ctrl+C aby zakonczyc)");
        // nagłówek kolumn z dopasowaną szerokością
        mvprintw(1,0, "idx | %-*s | %-*s | %*s | %-*s | %*s | %-*s",
            COL_SSID, "SSID",
            COL_BSSID, "BSSID",
            COL_CH, "CH",
            COL_ENC, "ENC",
            COL_RSSI, "RSSI",
            COL_VENDOR, "VENDOR");
        int r = 2;
        int ii = 0;
        for (size_t idx = 0; idx < snap.size(); ++idx) {
            APInfo &a = snap[idx];
            std::string disp_ssid = a.ssid;
            if (disp_ssid.size() > (size_t)COL_SSID) disp_ssid = disp_ssid.substr(0,COL_SSID);
            const char *rcol = C_RESET;
            if (a.max_rssi >= -60) rcol = C_GREEN;
            else if (a.max_rssi >= -80) rcol = C_YELLOW;
            else rcol = C_RED;
            // highlight kursora
            if ((int)idx == cursor) attron(A_REVERSE);
            mvprintw(r++, 0, "%3d | %-*s | %-*s | %*d | %-*s | %*d | %-*s",
                ii,
                COL_SSID, disp_ssid.c_str(),
                COL_BSSID, a.bssid.c_str(),
                COL_CH, a.channel,
                COL_ENC, a.enc.c_str(),
                COL_RSSI, (int)a.max_rssi,
                COL_VENDOR, a.vendor.c_str());
            if ((int)idx == cursor) attroff(A_REVERSE);
            ++ii;
            if (r >= LINES-1) break;
        }
        refresh();

        // obsługa klawiszy kursora i Enter
        int ch = getch();
        if (ch == 'q' || ch == 'Q') { stop_flag = 1; break; }
        else if (ch == KEY_UP) { if (cursor > 0) --cursor; }
        else if (ch == KEY_DOWN) { if (cursor + 1 < (int)snap.size()) ++cursor; }
        else if (ch == KEY_ENTER || ch == 10 || ch == 13) { selected_ap = cursor; stop_flag = 1; break; }

        std::this_thread::sleep_for(std::chrono::milliseconds(300));
    }

    // zakończ ncurses i wróć do normalnego trybu
    endwin();
    // Resetujemy flagę, aby kolejne użycie Ctrl+C przerwało główną pętlę przechwytywania
    stop_flag = 0;

    // Wyświetl znalezione AP w tabeli (posortowane po RSSI). Jeśli użytkownik
    // wybrał AP w ncurses (selected_ap >= 0), użyj tego wyboru.
    std::vector<APInfo> list;
    int i = 0;
    std::vector<APInfo> snap_final;
    {
        std::lock_guard<std::mutex> lk(aps_mtx);
        for (auto &kv : aps) snap_final.push_back(kv.second);
    }
    std::sort(snap_final.begin(), snap_final.end(), [](const APInfo &a, const APInfo &b){ return a.max_rssi > b.max_rssi; });
    list = snap_final;

    std::cout << "\nZnalezione sieci:\n\n";
    std::cout << "idx  | " << std::left << std::setw(COL_SSID) << "SSID" << " | "
              << std::left << std::setw(COL_BSSID) << "BSSID" << " | "
              << std::right << std::setw(COL_CH) << "CH" << " | "
              << std::left << std::setw(COL_ENC) << "ENC" << " | "
              << std::right << std::setw(COL_RSSI) << "RSSI" << " | "
              << std::left << std::setw(COL_VENDOR) << "VENDOR" << "\n";
    std::cout << std::string(120, '-') << "\n";
    for (auto &a : list) {
        // koloruj RSSI: >= -60 zielony, -80..-61 żółty, < -80 czerwony
        const char *rcol = C_RESET;
        if (a.max_rssi >= -60) rcol = C_GREEN;
        else if (a.max_rssi >= -80) rcol = C_YELLOW;
        else rcol = C_RED;

        std::ostringstream oss;
        std::string disp = a.ssid;
        if (disp.size() > (size_t)COL_SSID) disp = disp.substr(0,COL_SSID);
        oss << std::setw(3) << i << "  | " << std::left << std::setw(COL_SSID) << disp << " | "
            << std::left << std::setw(COL_BSSID) << a.bssid << " | " << std::right << std::setw(COL_CH) << a.channel << " | "
            << std::left << std::setw(COL_ENC) << a.enc << " | "
            << rcol << std::right << std::setw(COL_RSSI) << (int)a.max_rssi << C_RESET << " | "
            << std::left << std::setw(COL_VENDOR) << a.vendor;
        std::cout << oss.str() << "\n\n";
        ++i;
    }

    if (list.empty()) {
        std::cout << "Nie znaleziono sieci. Kończę.\n";
        pcap_close(global_handle);
        pcap_freealldevs(alldevs);
        return 0;
    }

    int ap_choice = -1;
    // jeśli użytkownik wybrał wcześniej przez ncurses, użyj tego wyboru
    if (selected_ap >= 0 && selected_ap < (int)list.size()) {
        ap_choice = selected_ap;
        std::cout << "Wybrano (ncurses): idx=" << ap_choice << " -> " << list[ap_choice].ssid << "\n";
    } else {
        std::cout << "Wybierz sieć do przechwytywania (idx): ";
        std::cin >> ap_choice;
        if (ap_choice < 0 || ap_choice >= (int)list.size()) {
            std::cerr << "Nieprawidłowy wybór.\n";
            pcap_close(global_handle);
            pcap_freealldevs(alldevs);
            return 1;
        }
    }

    APInfo target = list[ap_choice];
    std::cout << "Wybrano: " << target.ssid << " (" << target.bssid << ")\n";

    // Przygotuj filtr aby łapać pakiety związane z wybraną siecią
    char filter_expr[256];
    std::snprintf(filter_expr, sizeof(filter_expr),
        "wlan addr1 %s or wlan addr2 %s or wlan addr3 %s",
        target.bssid.c_str(), target.bssid.c_str(), target.bssid.c_str());

    if (pcap_compile(global_handle, &fp, filter_expr, 1, PCAP_NETMASK_UNKNOWN) == -1) {
        std::cerr << "pcap_compile (capture filter) failed: " << pcap_geterr(global_handle) << "\n";
    } else {
        if (pcap_setfilter(global_handle, &fp) == -1) {
            std::cerr << "pcap_setfilter (capture) failed: " << pcap_geterr(global_handle) << "\n";
        }
        pcap_freecode(&fp);
    }

    // Poproś o nazwę pliku wyjściowego. Jeśli użytkownik wciśnie Enter bez niczego,
    // wygenerujemy nazwę domyślną według `auto_name_format`. Jeśli podano `--out-dir`, zapiszemy w tym katalogu.
    std::string outfile;
    std::cout << "Nazwa pliku do zapisu (.pcap) [" << auto_name_format << "]: ";
    std::string tmp;
    std::getline(std::cin, tmp); // skasuj pozostały newline po wcześniejszym wejściu
    std::getline(std::cin, outfile);
    auto make_filename_from_format = [&](const std::string &fmt)->std::string{
        time_t t = time(nullptr);
        struct tm *lt = localtime(&t);
        char buf[256];
        if (lt) strftime(buf, sizeof(buf), fmt.c_str(), lt);
        else std::snprintf(buf, sizeof(buf), "%lld", (long long)t);
        return std::string(buf);
    };
    if (outfile.empty()) {
        outfile = make_filename_from_format(auto_name_format);
        std::cout << "Używam domyślnej nazwy: " << outfile << "\n";
    }
    // jeśli podano katalog wyjściowy, stwórz go jeśli nie istnieje i połącz ścieżki
    if (!out_dir.empty()) {
        struct stat st;
        if (stat(out_dir.c_str(), &st) != 0) {
            // spróbuj utworzyć katalog (nie rekurencyjnie)
            if (mkdir(out_dir.c_str(), 0755) != 0) {
                std::cerr << "Nie można utworzyć katalogu wyjściowego: " << out_dir << "\n";
            }
        }
        // połącz
        if (!out_dir.empty() && out_dir.back() == '/') outfile = out_dir + outfile; else outfile = out_dir + "/" + outfile;
    }

    // Otwórz dumper
    global_dumper = pcap_dump_open(global_handle, outfile.c_str());
    if (!global_dumper) {
        std::cerr << "pcap_dump_open nie powiodło się: " << pcap_geterr(global_handle) << "\n";
        pcap_close(global_handle);
        pcap_freealldevs(alldevs);
        return 1;
    }

    // Jeśli eapol_dump_enabled, przygotuj plik EAPOL (domyślna nazwa eapol_<timestamp>.pcap)
    pcap_dumper_t *eapol_dumper = nullptr;
    std::string current_eapol_file;
    // Plik na wykryte PMKID-y (format: PMKID*APMAC*STAMAC*PMKID*ESSID) — akceptowany przez hashcat/hcx-tools
    std::ofstream pmkid_ofs;
    std::string pmkid_file;
    if (eapol_dump_enabled) {
        if (!eapol_dump_file.empty()) {
            current_eapol_file = eapol_dump_file;
        } else {
            std::string ef = outfile;
            // spróbuj zamienić "capture" na "eapol" w nazwie, jeśli obecna
            size_t pos = ef.find("capture");
            if (pos != std::string::npos) ef.replace(pos, 7, "eapol");
            else ef = std::string("eapol_") + ef;
            current_eapol_file = ef;
        }
        eapol_dumper = pcap_dump_open(global_handle, current_eapol_file.c_str());
        if (!eapol_dumper) {
            std::cerr << "Nie można utworzyć pliku EAPOL: " << current_eapol_file << " (" << pcap_geterr(global_handle) << ")\n";
            // nie przerywamy, tylko wyłączamy eapol dump
            eapol_dumper = nullptr;
            eapol_dump_enabled = false;
        } else {
            std::cout << "Zapis EAPOL do: " << current_eapol_file << "\n";
        }
    }

    // przygotuj plik PMKID jeśli możliwe (nazwę tworzymy obok pliku pcap lub używamy --pmkid-out)
    auto make_pmkid_filename = [&](const std::string &base)->std::string{
        std::string out = base;
        // jeśli kończy się na .pcap, zamień na .pmkid
        size_t pos = out.rfind(".pcap");
        if (pos != std::string::npos) out.replace(pos, 5, ".pmkid"); else out += ".pmkid";
        return out;
    };
    if (!pmkid_out_arg.empty()) {
        pmkid_file = pmkid_out_arg;
    } else if (!outfile.empty()) {
        pmkid_file = make_pmkid_filename(outfile);
    }
    if (!pmkid_file.empty()) {
        pmkid_ofs.open(pmkid_file, std::ios::out | std::ios::app);
        if (pmkid_ofs) std::cout << "PMKID: zapisywanie do: " << pmkid_file << "\n";
        else pmkid_file.clear();
    }

    // Zarejestruj handler Ctrl+C
    std::signal(SIGINT, handle_sigint);

    std::cout << "Rozpoczynam przechwytywanie dla " << target.ssid << ". Naciśnij Ctrl+C, aby zakończyć.\n";

    // Struktury do zbierania handshake'ów EAPOL (per AP<->STA)
    struct HSKBuf {
        std::vector<std::pair<struct pcap_pkthdr, std::vector<u_char>>> frames;
        int mic_count = 0;
        time_t first_ts = 0;
        bool dumped = false;
    };
    std::map<std::string, HSKBuf> hsk_map; // key = apmac + '|' + stamac

    // Pętla przechwytywania — zapisujemy pakiety do pliku
    // Jeśli użytkownik podał -t/--time, przechwytywanie zakończy się po tej liczbie sekund.
    // Jeśli nie podano limitu czasu, zakończymy przechwytywanie po wykryciu 3 ramek EAPOL (typ 0x888e).
    time_t start_ts = time(nullptr);
    int eapol_count = 0;
    time_t file_start_ts = start_ts;
    std::string current_outfile = outfile;
    while (!stop_flag) {
        struct pcap_pkthdr *h;
        const u_char *pkt;
        int res = pcap_next_ex(global_handle, &h, &pkt);
        if (res == 1) {
            // Zapisz pakiet
            pcap_dump(reinterpret_cast<u_char*>(global_dumper), h, pkt);
            // Szybkie skanowanie bufora w poszukiwaniu sekwencji 0x88 0x8e (EAPOL)
            bool found_eapol = false;
            if (h->caplen >= 2) {
                for (u_int i = 0; i + 1 < h->caplen; ++i) {
                    if (pkt[i] == 0x88 && pkt[i+1] == 0x8e) { found_eapol = true; break; }
                }
            }
            if (found_eapol) {
                ++eapol_count;
                if (eapol_dump_enabled && eapol_dumper) {
                    // zapisz ramkę EAPOL do oddzielnego pliku
                    pcap_dump(reinterpret_cast<u_char*>(eapol_dumper), h, pkt);
                }
                // Wyciągnij MAC AP i STA z nagłówka 802.11 (po radiotap)
                uint16_t rt_len_local = 0;
                if (h->caplen >= 4) rt_len_local = *(const uint16_t*)(pkt + 2);
                if (rt_len_local != 0 && rt_len_local + 24 <= h->caplen) {
                    const u_char *dot11_local = pkt + rt_len_local;
                    std::string apmac_local = mac_to_str(dot11_local + 16); // addr3
                    std::string stamac_local = mac_to_str(dot11_local + 10); // addr2

                    // Buforuj ramkę w hsk_map
                    std::string key = apmac_local + "|" + stamac_local;
                    auto &hb = hsk_map[key];
                    if (hb.frames.empty()) hb.first_ts = h->ts.tv_sec;
                    // skopiuj nagłówek i payload
                    struct pcap_pkthdr ph = *h;
                    std::vector<u_char> data(pkt, pkt + h->caplen);
                    hb.frames.emplace_back(ph, std::move(data));

                    // Spróbuj rozpoznać czy EAPOL-Key ma MIC
                    const u_char *eapol_ptr = nullptr;
                    int eapol_off = -1;
                    for (u_int i = 0; i + 1 < h->caplen; ++i) {
                        if (pkt[i] == 0x88 && pkt[i+1] == 0x8e) { eapol_ptr = pkt + i; eapol_off = i; break; }
                    }
                    if (eapol_ptr) {
                        int remain = h->caplen - eapol_off;
                        if (remain >= 99) {
                            uint8_t eapol_type = eapol_ptr[1];
                            if (eapol_type == 3) {
                                // key_info at eapol_ptr + 5..6 (relative to eapol start+4)
                                const u_char *key_info_p = eapol_ptr + 4 + 1; // relative
                                uint16_t key_info = *(const uint16_t*)key_info_p;
                                // check MIC bit (bit 8 of key_info when read little/big?) — heuristic: if MIC bytes non-zero in expected MIC pos
                                const u_char *micp = eapol_ptr + 4 + 77; // key MIC offset relative to eapol start
                                bool has_mic = false;
                                if (remain >= 93) {
                                    // check if MIC not all zero
                                    has_mic = false;
                                    for (int z=0; z<16; ++z) if (micp[z] != 0) { has_mic = true; break; }
                                }
                                if (has_mic) hb.mic_count++;
                            }
                        }
                    }

                    // Warunek zapisania handshake: co najmniej 4 ramek lub 2 z MIC
                    if (!hb.dumped && (hb.frames.size() >= 4 || hb.mic_count >= 2)) {
                        // przygotuj nazwę pliku pcap dla handshake
                        char tbuf[64];
                        time_t nowt = time(nullptr);
                        struct tm *lt = localtime(&nowt);
                        strftime(tbuf, sizeof(tbuf), "%Y%m%d_%H%M%S", lt);
                        std::string clean_ap = apmac_local; for (char &c: clean_ap) if (c==':') c='-';
                        std::string clean_sta = stamac_local; for (char &c: clean_sta) if (c==':') c='-';
                        std::string hpcap = std::string("handshake_") + clean_ap + "_" + clean_sta + "_" + tbuf + ".pcap";
                        if (!handshake_out_dir.empty()) {
                            if (handshake_out_dir.back() == '/') hpcap = handshake_out_dir + hpcap; else hpcap = handshake_out_dir + "/" + hpcap;
                        }
                        pcap_dumper_t *hd = pcap_dump_open(global_handle, hpcap.c_str());
                        if (hd) {
                            for (auto &fp : hb.frames) {
                                pcap_dump(reinterpret_cast<u_char*>(hd), &fp.first, fp.second.data());
                            }
                            pcap_dump_close(hd);
                            std::cout << C_CYAN << "Zapisano handshake pcap: " << hpcap << C_RESET << "\n";
                        } else {
                            std::cerr << "Nie mozna zapisac handshake pcap: " << hpcap << "\n";
                        }
                        // zapis podsumowania tekstowego (ANonce/SNonce/MIC jeśli dostępne)
                        std::string htxt = hpcap + ".txt";
                        std::ofstream hf(htxt);
                        if (hf) {
                            hf << "AP=" << apmac_local << "\n";
                            hf << "STA=" << stamac_local << "\n";
                            hf << "frames=" << hb.frames.size() << "\n";
                            hf << "mic_count=" << hb.mic_count << "\n";
                            hf.close();
                            std::cout << C_CYAN << "Zapisano handshake summary: " << htxt << C_RESET << "\n";
                        }
                        hb.dumped = true;
                    }
                }
                // Dodatkowo spróbuj wykryć PMKID w polu Key Data EAPOL-Key
                // Szukamy sekwencji 0x88 0x8e i traktujemy jej pozycję jako początek EAPOL
                for (u_int i = 0; i + 1 < h->caplen; ++i) {
                    if (!(pkt[i] == 0x88 && pkt[i+1] == 0x8e)) continue;
                    const u_char *eapol = pkt + i;
                    int remain = h->caplen - i;
                    // Potrzebujemy co najmniej 4 bajty (EAPOL header) + 97 bajtów stałej części EAPOL-Key
                    if (remain < 101) continue;
                    uint8_t eapol_type = eapol[1];
                    if (eapol_type != 3) continue; // interesują nas tylko EAPOL-Key
                    // key_data_length jest na offsetcie 97 od początku EAPOL (4 bytes header + 93)
                    uint16_t key_data_len = ntohs(*(const uint16_t*)(eapol + 97));
                    if ((int)key_data_len <= 0) continue;
                    if (remain < 99 + key_data_len) continue;
                    const u_char *key_data = eapol + 99;
                    int kd_rem = key_data_len;

                    // Spróbuj znaleźć PMKID: RSN PMKID list ma postać: 2 bajty count + count*16 bajtów PMKID
                    for (int off = 0; off + 2 <= kd_rem; ++off) {
                        uint16_t cnt_be = ntohs(*(const uint16_t*)(key_data + off));
                        uint16_t cnt_le = *(const uint16_t*)(key_data + off);
                        uint16_t cnt = 0;
                        // wybierz sensowną interpretację (niezerową i mieszczącą się)
                        if (cnt_be > 0 && (int)cnt_be * 16 <= kd_rem - (off + 2)) cnt = cnt_be;
                        else if (cnt_le > 0 && (int)cnt_le * 16 <= kd_rem - (off + 2)) cnt = cnt_le;
                        if (cnt == 0) continue;
                        // mamy listę PMKID-ów
                        for (uint16_t pi = 0; pi < cnt; ++pi) {
                            const u_char *pm = key_data + off + 2 + pi * 16;
                            // przygotuj hex PMKID
                            char ph[33+1];
                            for (int z = 0; z < 16; ++z) std::sprintf(ph + z*2, "%02x", pm[z]);
                            ph[32] = '\0';

                            // Wyciągnij MAC AP i STA z nagłówka 802.11 (po radiotap)
                            uint16_t rt_len = 0;
                            if (h->caplen >= 4) rt_len = *(const uint16_t*)(pkt + 2);
                            if (rt_len == 0 || rt_len + 24 > h->caplen) {
                                // nie udało się odczytać nagłówka 802.11
                                continue;
                            }
                            const u_char *dot11 = pkt + rt_len;
                            const u_char *addr1 = dot11 + 4;
                            const u_char *addr2 = dot11 + 10;
                            const u_char *addr3 = dot11 + 16;
                            std::string apmac = mac_to_str(addr3);
                            std::string stamac = mac_to_str(addr2);

                            // lookup SSID jeśli mamy w mapie
                            std::string ssid = "";
                            {
                                std::lock_guard<std::mutex> lk(aps_mtx);
                                auto it = aps.find(apmac);
                                if (it != aps.end()) ssid = it->second.ssid;
                            }
                            if (ssid.empty()) ssid = target.ssid;
                            // escape quotes/newlines
                            for (char &c: ssid) if (c == '"' || c == '\n' || c == '\r') c = '_';

                            // Zapisz linię w formacie akceptowanym przez hashcat/hcx-tools
                            if (!pmkid_file.empty() && pmkid_ofs) {
                                pmkid_ofs << ph << "*" << apmac << "*" << stamac << "*" << ssid << "\n";
                                pmkid_ofs.flush();
                            }
                            std::cout << C_CYAN << "PMKID wykryty: " << ph << " (" << apmac << "*" << stamac << ") ssid='" << ssid << "'" << C_RESET << "\n";
                        }
                        // Po znalezieniu PMKID nie szukaj dalej w tym key_data (unikamy duplikatów)
                        break;
                    }
                }
            }
        } else if (res == 0) {
            // timeout, kontynuuj
            continue;
        } else if (res == -1) {
            std::cerr << "Błąd podczas czytania pakietu: " << pcap_geterr(global_handle) << "\n";
            break;
        } else if (res == -2) {
            // EOF
            break;
        }

        // Sprawdź warunki zakończenia
        if (capture_time > 0) {
            if (difftime(time(nullptr), start_ts) >= capture_time) {
                std::cout << "Koniec: osiągnięto limit czasu (" << capture_time << "s).\n";
                break;
            }
        } else {
            if (eapol_count >= eapol_threshold) {
                std::cout << "Koniec: wykryto " << eapol_threshold << " ramek EAPOL (przybliżenie hashy).\n";
                break;
            }
        }
        // obsługa rotacji czasowej pliku pcap
        if (rotate_time > 0) {
            if (difftime(time(nullptr), file_start_ts) >= rotate_time) {
                // zamknij aktualnego dumpersa i otwórz nowego
                if (global_dumper) { pcap_dump_close(global_dumper); global_dumper = nullptr; }
                if (eapol_dumper) { pcap_dump_close(eapol_dumper); eapol_dumper = nullptr; }
                // wygeneruj nową nazwę bazując na formatcie i aktualnym czasie
                std::string newname = make_filename_from_format(auto_name_format);
                if (!out_dir.empty()) {
                    if (!out_dir.empty() && out_dir.back() == '/') newname = out_dir + newname; else newname = out_dir + "/" + newname;
                }
                current_outfile = newname;
                global_dumper = pcap_dump_open(global_handle, current_outfile.c_str());
                if (!global_dumper) {
                    std::cerr << "Rotacja: nie można otworzyć nowego pliku pcap: " << current_outfile << "\n";
                } else {
                    std::cout << "Rotacja: nowy plik: " << current_outfile << "\n";
                }
                if (eapol_dump_enabled) {
                    std::string newe = current_outfile;
                    size_t pos = newe.find("capture");
                    if (pos != std::string::npos) newe.replace(pos, 7, "eapol"); else newe = std::string("eapol_") + newe;
                    current_eapol_file = newe;
                    eapol_dumper = pcap_dump_open(global_handle, current_eapol_file.c_str());
                    if (!eapol_dumper) {
                        std::cerr << "Rotacja: nie można otworzyć pliku EAPOL: " << current_eapol_file << "\n";
                        eapol_dump_enabled = false;
                    }
                }
                file_start_ts = time(nullptr);
            }
        }
    }
    std::cout << "Pętla przechwytywania zakończona.\n";

    // Sprzątanie: zamknij pliki i przywróć interfejs jeśli trzeba
    if (global_dumper) pcap_dump_close(global_dumper);
    if (global_handle) pcap_close(global_handle);
    pcap_freealldevs(alldevs);

    // Jeśli podano --json <file>, zapisz listę znalezionych AP i metadane do JSON
    if (!json_out_file.empty()) {
        std::ofstream jf(json_out_file);
        if (jf) {
            jf << "[\n";
            for (size_t ii = 0; ii < list.size(); ++ii) {
                auto &a = list[ii];
                // proste escaping dla cudzysłowów w SSID
                std::string ssid = a.ssid;
                for (char &c: ssid) if (c == '"') c = '\'';
                jf << "  {\"ssid\": \"" << ssid << "\", \"bssid\": \"" << a.bssid << "\", ";
                jf << "\"channel\": " << a.channel << ", \"enc\": \"" << a.enc << "\", ";
                jf << "\"rssi\": " << (int)a.max_rssi << ", \"vendor\": \"" << a.vendor << "\" }";
                if (ii + 1 < list.size()) jf << ",\n"; else jf << "\n";
            }
            jf << "]\n";
            jf.close();
            std::cout << "Zapisano metadane do JSON: " << json_out_file << "\n";
        } else {
            std::cerr << "Nie można otworzyć pliku JSON do zapisu: " << json_out_file << "\n";
        }
    }

    if (monitor_enabled) {
        std::cout << "Przywracam interfejs do trybu managed...\n";
        std::string cmd_down = "sudo ip link set " + selected_iface + " down";
        std::string cmd_man = "sudo iw dev " + selected_iface + " set type managed";
        std::string cmd_up = "sudo ip link set " + selected_iface + " up";
        system(cmd_down.c_str());
        system(cmd_man.c_str());
        system(cmd_up.c_str());
    }

    std::cout << "Zapisano do pliku: " << outfile << "\n";
    std::cout << "Koniec.\n";
    return 0;
}