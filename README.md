# Factorspace - HackMyVM (Medium)

![Factorspace.png](Factorspace.png)

## Übersicht

*   **VM:** Factorspace
*   **Plattform:** [HackMyVM](https://hackmyvm.eu/machines/machine.php?vm=Factorspace)
*   **Schwierigkeit:** Medium
*   **Autor der VM:** DarkSpirit
*   **Datum des Writeups:** 23. Juli 2023
*   **Original-Writeup:** https://alientec1908.github.io/Factorspace_HackMyVM_Medium/
*   **Autor:** Ben C.

## Kurzbeschreibung

Das Ziel dieser Challenge war die Kompromittierung der virtuellen Maschine "Factorspace" auf der HackMyVM-Plattform, um sowohl die User- als auch die Root-Flag zu erlangen. Der Lösungsweg begann mit Web-Enumeration und der Entdeckung einer Login-Seite. Nach erfolgreichem Login (wahrscheinlich durch Erraten eines schwachen Passworts) wurde eine Suchfunktion identifiziert, die anfällig für XPath-Injection war. Über diese Schwachstelle konnten E-Mail-Adressen und Klartext-Passwörter extrahiert werden. Mit einem dieser Passwort-Username-Paare wurde initialer Zugriff per SSH als Benutzer `jackie` erlangt. Die anschließende Privilege Escalation zu `root` erfolgte durch das Mitschneiden eines privaten SSH-Schlüssels für den Root-Benutzer, der unverschlüsselt über einen UDP-Multicast-Dienst im Netzwerk verbreitet wurde.

## Disclaimer / Wichtiger Hinweis

Die in diesem Writeup beschriebenen Techniken und Werkzeuge dienen ausschließlich zu Bildungszwecken im Rahmen von legalen Capture-The-Flag (CTF)-Wettbewerben und Penetrationstests auf Systemen, für die eine ausdrückliche Genehmigung vorliegt. Die Anwendung dieser Methoden auf Systeme ohne Erlaubnis ist illegal. Der Autor übernimmt keine Verantwortung für missbräuchliche Verwendung der hier geteilten Informationen. Handeln Sie stets ethisch und verantwortungsbewusst.

## Verwendete Tools

*   `arp-scan`
*   `nmap`
*   `vi` / `nano`
*   `nikto`
*   `gobuster`
*   Web Browser
*   `ssh`
*   `ls`, `cat`
*   `ss`
*   `socat`
*   `chmod`
*   Standard Linux-Befehle (`cd`, etc.)

## Lösungsweg (Zusammenfassung)

Der Angriff auf die Maschine "Factorspace" gliederte sich in folgende Phasen:

1.  **Reconnaissance & Enumeration:**
    *   IP-Findung mittels `arp-scan` (192.168.2.124), Hostname `factor.hmv` in `/etc/hosts` eingetragen.
    *   Umfassender Portscan mit `nmap` identifizierte offene Ports: 22/tcp (OpenSSH 8.4p1 Debian) und 80/tcp (Apache 2.4.56 Debian, Titel "industrial").

2.  **Web Enumeration & Exploit (XPath Injection):**
    *   `nikto` und `gobuster` fanden u.a. `/login.php`, `/results.php` und `/auth.php`.
    *   Manuelle Untersuchung der `/login.php` führte (nach Annahme erfolgreicher Credentials, z.B. `admin`:`iloveyou`) zu einer Suchfunktion (`employee_search_filter.html`).
    *   Die Suchfunktion war anfällig für XPath-Injection. Durch Injektionen wie `' or 1=1]/email | //abc[abc='` und `' or 1=1]/password | //abc[abc='` konnten E-Mail-Adressen und Klartext-Passwörter aus dem Backend (vermutlich XML) extrahiert werden, darunter `jackie.chan@factorspace.hmv` mit dem Passwort `qyxG27KGkW0x9SJ1`.

3.  **Initial Access (SSH):**
    *   Der Versuch, sich mit den extrahierten Credentials per SSH als `john` anzumelden, scheiterte.
    *   Der Login als `jackie` mit dem Passwort `qyxG27KGkW0x9SJ1` war erfolgreich und gewährte initialen Zugriff auf das System. Die User-Flag wurde im Home-Verzeichnis von `jackie` gefunden.

4.  **Privilege Escalation (Multicast Sniffing & SSH Key):**
    *   `sudo -l` für `jackie` war nicht verfügbar.
    *   Die Ausgabe von `ss -altpnu` zeigte einen verdächtigen UDP-Listener auf der Multicast-Adresse `224.1.1.1` Port `5555`.
    *   Auf der Angreifer-Maschine wurde `socat UDP4-RECVFROM:5555,ip-add-membership=224.1.1.1:0.0.0.0 -` verwendet, um den Multicast-Traffic mitzuschneiden.
    *   Kurz darauf wurde ein vollständiger privater OpenSSH-Schlüssel für `root@factorspace` über den Multicast-Strom empfangen.
    *   Der private Schlüssel wurde auf dem Zielsystem (oder der Angreifer-Maschine) gespeichert, die Berechtigungen gesetzt (`chmod 600`) und für einen SSH-Login als `root` verwendet (`ssh root@localhost -i <schlüsseldatei>`).
    *   Der Root-Login war erfolgreich. Die Root-Flag wurde gelesen.

## Wichtige Schwachstellen und Konzepte

*   **XPath Injection:** Eine Schwachstelle in der Webanwendung erlaubte es, durch speziell präparierte Eingaben die Struktur von XPath-Abfragen zu manipulieren und so unautorisiert auf Daten im Backend (vermutlich XML-basiert) zuzugreifen. Dies führte zur Preisgabe von Benutzernamen und Klartext-Passwörtern.
*   **Schwache Passwörter / Passwort-Wiederverwendung:** Der initiale Login in die Webanwendung gelang vermutlich durch ein schwaches Passwort. Die über XPath Injection erlangten Passwörter waren teilweise für den SSH-Zugang gültig, was auf Passwort-Wiederverwendung hindeutet.
*   **Information Disclosure über Multicast (SSH Private Key Leak):** Ein extrem unsicherer Mechanismus verbreitete den privaten SSH-Schlüssel des Root-Benutzers unverschlüsselt über einen UDP-Multicast-Strom im Netzwerk. Jeder, der sich dieser Multicast-Gruppe anschloss, konnte den Schlüssel mitschneiden.
*   **Unsichere Netzwerkdienste:** Das Betreiben eines ungesicherten Multicast-Dienstes, der sensible Daten wie private Schlüssel überträgt, stellt ein erhebliches Sicherheitsrisiko dar.

## Flags

*   **User Flag (`/home/jackie/user.txt`):** `eb7d964a2a41006bb325cf822db664be`
*   **Root Flag (`/root/root.txt`):** `052cf26a6e7e33790391c0d869e2e40c`

## Tags

`HackMyVM`, `Factorspace`, `Medium`, `XPathInjection`, `PasswordLeak`, `Multicast`, `SSHPrivateKeyLeak`, `InformationDisclosure`, `Linux`, `Web`, `Privilege Escalation`
