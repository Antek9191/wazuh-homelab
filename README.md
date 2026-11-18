[README.md](https://github.com/user-attachments/files/35046010/README.md)
# Home Lab SOC — Wazuh: Wykrywanie i analiza ataków

## 1. Wprowadzenie

Home lab SOC na Wazuh, robiony głównie pod CV, bo same kursy, CCNA i Security+ bez certyfikatów, to za mało. Ale po drodze mnie to wciągnęło i chciałem kopać dalej.

Podchodziłem do tego z perspektywy L1, próbując realnie wykryć i ocenić alerty, a nie tylko odpalać ataki. Część wniosków poniżej to błędne tropy z początku, zostawiam je bo pokazują proces.

## 2. Architektura labu

Trzy maszyny, sieć host-only VirtualBoxa, 192.168.56.0/24. Arch to host i atakujący, Hydra i Nmap. Ubuntu 26.04.1 LTS, 192.168.56.101, to manager Wazuh. Fedora 44, 192.168.56.102, to agent i cel ataków, tam też stoi Suricata.

Wazuh v4.14.9, Suricata 8.0.8.

FIM na agencie:
```xml
<syscheck>
  <disabled>no</disabled>
  <directories realtime="yes" check_all="yes">/tmp</directories>
  <directories check_all="yes" report_changes="yes" realtime="yes">/root</directories>
  <directories>/etc,/usr/bin,/usr/sbin,/bin,/sbin,/boot</directories>
  <frequency>43200</frequency>
  <scan_on_start>yes</scan_on_start>
</syscheck>
```
`/tmp` i `/root` w czasie rzeczywistym, reszta co 12h.

Integracja VirusTotal na managerze:
```xml
<integration>
  <name>virustotal</name>
  <api_key><KLUCZ_API_VIRUSTOTAL></api_key>
  <group>syscheck</group>
  <alert_format>json</alert_format>
</integration>
```

### 2a. Wstępny triage, szum systemowy

Przejrzałem pierwszy eksport logów zanim zacząłem konkretne ataki, żeby odróżnić szum od czegoś realnego.

Rootcheck zgłosił 20 alertów "Trojaned version of file" na zwykłych binarkach, `ls`, `cat`, `env` i inne. Sygnatura szuka ciągów typu `bash` czy `/dev/`, które naturalnie są w coreutils. Podwójne alerty bo `/bin` to symlink do `/usr/bin`. Sprawdziłem `dpkg -V coreutils`, nic nie zmienione. False positive.

Reguła 533, netstat, zgłosiła zmianę portów po restarcie agenta, tylko inne PID-y. Normalne.

## 3. Scenariusz 1 — Enumeracja i Brute Force SSH

Atak szedł z Ubuntu, 192.168.56.101, na Fedorę, 192.168.56.102. Użyłem Hydry z plikami `userlist.txt` i `passlist.txt`.

Najpierw enumeracja kont, próby logowania na nieistniejące konta `admin` i `ubuntu`, 3 listopada ok. 19:31 i 19:44. Wazuh złapał to regułą 5710, "Attempt to login using a non-existent user".

Potem brute force na konto `testuser`, kilka fal między 13:01 a 14:17. Widać serie równoległych nieudanych logowań, kilka prób w tej samej sekundzie z różnych portów źródłowych, co pasuje do narzędzia działającego automatycznie, a nie człowieka klikającego ręcznie. Reguła 5760 łapała pojedyncze nieudane próby, a po przekroczeniu progu, 8 błędów w 120 sekund z tego samego IP, odpaliła się reguła 5763, "sshd: brute force trying to get access to the system", poziom 10. To był najmocniejszy alert z tego scenariusza.

Najważniejsze: testuser w pewnym momencie zalogował się skutecznie, reguła 5715, w trakcie trwania serii brute force, o 13:17:40 i 14:05:54. Czyli hasło było w słowniku i zostało złamane. To realna kompromitacja konta w labie, nie tylko próba.

Dla porównania, próby na `root` (2 razy wieczorem 3 listopada) i na nieistniejącego użytkownika z literówką w wielkości liter nigdy się nie powiodły.

MITRE: enumeracja i brute force mapują się na T1110.001, Password Guessing, i T1021.004, SSH.

Wniosek z tego scenariusza: samo wykrycie próby logowania to nie wszystko, trzeba sprawdzić czy któraś się powiodła, bo to zmienia ocenę z "próba ataku" na "incydent z kompromitacją".

## 4. Scenariusz 2 — EICAR, wykrywanie malware przez FIM i VirusTotal

Klasyczny test pliku EICAR, pobrany przez `curl` z `secure.eicar.org`. Pierwsza próba na Archu się nie udała, bo Arch nie ma zainstalowanego agenta Wazuh, więc nic go nie widziało. Przeniosłem test na Fedorę.

Pipeline wygląda tak: plik ląduje w `/tmp/eicar.txt`, FIM w trybie realtime wykrywa dodanie pliku w ciągu kilku sekund, reguła 554, "File added to the system". Zaraz potem integracja VirusTotal sprawdza hash w tle i zwraca trafienie, reguła 87105, poziom 12, z liczbą silników antywirusowych które wykryły plik jako złośliwy, zwykle 65-66 z około 67-68.

Testowałem to trzy razy w różne dni, 10, 12 i 16 listopada, za każdym razem ten sam wynik. Hash się zgadza ze standardowym EICAR, sha256 275a021b...651fd0f.

MITRE: reguła 87105 mapuje się na T1203, Exploitation for Client Execution.

### 4a. Błędna interpretacja jako atak

Przy konfigurowaniu FIM, 10 listopada, edycja `ossec.conf` spowodowała błąd startu agenta, `wazuh-execd` zgłaszał błąd bez wskazania linii. Na tamtym etapie projektu miałem jeszcze mało logów do porównania, więc pomyślałem, że to może być ślad ataku, a nie mój własny błąd w configu. Po sprawdzeniu `journalctl` i `xmllint` okazało się że to zwykły błąd składni w sekcji syscheck. Naprawiłem to tego samego dnia, plik zapisany o 18:41:22, a pierwszy poprawny alert FIM pojawił się już o 18:46:40.

Podobnie z alertami AppArmor z tego samego wieczoru, fusermount3, ubuntu-insights, cupsd. Zbieżność czasowa z testami EICAR skłoniła mnie do sprawdzenia czy to nie jest powiązane. Po analizie pól `profile`, `comm` i `capname` okazało się że to rutynowe odmowy sandboxa dla zwykłych procesów systemowych, nic wspólnego z EICAR ani żadną moją celową akcją.

Wniosek: przy małej liczbie logów łatwo pomylić przypadkową zbieżność czasową z realnym powiązaniem. Trzeba sprawdzić konkretne pola, profil, proces, co dokładnie próbował zrobić, zanim się założy że coś jest atakiem.

## 5. Scenariusz 3 — Skanowanie portów i detekcja przez Suricatę

Nmap z Ubuntu na Fedorę, `nmap -sV 192.168.56.102`. Pierwsza próba nic nie dała, "Host seems down", bo domyślny ping probe nie przeszedł. Trzeba było dodać `-Pn` żeby pominąć ten krok.

Wynik skanu: jeden otwarty port, 22/tcp, OpenSSH 10.2.

Sam Wazuh bez dodatkowego źródła nic by nie zobaczył, bo skan portów to ruch sieciowy, nie coś co loguje agent HIDS. Ale miałem już skonfigurowaną Suricatę jako NIDS na Fedorze, z własną regułą:

```
alert tcp any any -> $HOME_NET any (
  msg:"LOCAL TCP SYN scan detected";
  flags:S,12;
  detection_filter: track by_src, count 20, seconds 5;
  classtype:attempted-recon;
  sid:1000001;
  rev:1;
)
```

Reguła łapie pakiety z flagą SYN i odpala alert dopiero jak ten sam adres źródłowy wyśle 20 pakietów SYN w 5 sekund. Zadziałało, skan został wykryty, Wazuh pokazał to jako rule.id 86601.

### 5a. Obserwacja do poprawy

Mimo progu w regule, skan wygenerował około tysiąca osobnych alertów, bo `detection_filter` działa jako bramka startowa, a nie jako realna agregacja. Po przekroczeniu progu Suricata i tak alertuje przy każdym kolejnym pakiecie pasującym do reguły bazowej. Lepszym rozwiązaniem byłby `threshold type limit` zamiast `detection_filter`, żeby ograniczyć faktyczny wolumen alertów podczas całego ataku, a nie tylko moment startu.

Wniosek z tego scenariusza: natywny Wazuh bez NIDS nie widzi skanów portów, to realna luka w czystym HIDS. Ale własna reguła w Suricacie w pełni to pokrywa, chociaż wymaga dopracowania pod kątem tuningu, bo sam fakt wykrycia to nie wszystko, trzeba jeszcze zadbać żeby dashboard nie zalało tysiącem alertów za jeden skan.

## 6. Lessons Learned

Kilka rzeczy, które wyniosłem z całego projektu, nie tylko z pojedynczych scenariuszy.

Przy małej liczbie logów łatwo pomylić przypadkową zbieżność czasową z realnym powiązaniem. Zdarzyło mi się to dwa razy, przy błędzie konfiguracji i przy AppArmor. Trzeba sprawdzić konkretne pola zanim się założy że coś jest atakiem.

Agent na Fedorze w pewnym momencie się rozłączył, zwykły problem z łącznością, "Transport endpoint is not connected". Sprawdziłem osobno manager, czy nasłuchuje na portach 1514 i 1515, i osobno agenta. Okazało się że to agent trzeba było zrestartować. Dobra lekcja, żeby sprawdzać obie strony połączenia osobno, a nie zgadywać gdzie jest problem.

Różnica między `detection_filter` a `threshold` w Suricacie, opisana w scenariuszu 3, pokazuje że sama reguła wykrywająca coś poprawnie to nie koniec roboty, trzeba jeszcze pomyśleć o tym jak dużo szumu generuje w praktyce.

I ogólnie, HIDS sam z siebie ma swoje granice, bez NIDS nie widzi ruchu sieciowego. To nie jest wada Wazuha, tylko czegoś co trzeba wiedzieć zanim się buduje cały lab tylko na jednym typie detekcji.

## 7. Bezpieczeństwo danych w tym repo

Klucz API VirusTotal w configach jest zamaskowany jako `<KLUCZ_API_VIRUSTOTAL>`, prawdziwy klucz nigdy nie trafił do repo. Konta typu `testuser` i pliki `userlist.txt`/`passlist.txt` to dane testowe z labu, nie prawdziwe poświadczenia do czegokolwiek. Adresy IP w dokumencie to prywatna sieć 192.168.56.x, host-only VirtualBoxa, nic wrażliwego.
