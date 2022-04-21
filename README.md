# co2fhem
# co2mini

## Quellen / Links

https://github.com/henryk/fhem-co2mini

https://forum.fhem.de/index.php?topic=41750.0

https://hackaday.io/project/5301-reverse-engineering-a-low-cost-usb-co-monitor



# Installation allgemein

Im folgenden ist die Installation für folgendes Setup beschrieben:

![Setup](https://github.com/jliebich/RaspberryPiNotes/blob/master/bilder/co2mini_Setup.png)

Dateien von hier

        https://github.com/verybadsoldier/fhem-co2mini/tree/vbs
        
oder hier

        https://github.com/henryk/fhem-co2mini/tree/verybadsoldier-vbs
        
auf den Raspi herunterladen, der mit dem CO2mini via USB verbunden ist (hier IP 192.168.0.36).
Darauf achten, dass man nicht die veraltete Version von FHEM/38_co2mini.pm bekommt.
Die richtige ist vom 24.01.2016 / 10.046 Bytes

        cd /etc/udev/rules.d

Datei 90-co2mini.rules mit folgendem Inhalt anlegen

    ACTION=="remove", GOTO="co2mini_end"
    SUBSYSTEMS=="usb", KERNEL=="hidraw*", ATTRS{idVendor}=="04d9", ATTRS{idProduct}=="a052", GROUP="plugdev", MODE="0660", SYMLINK+="co2mini%n", GOTO="co2mini_end"
    LABEL="co2mini_end"

Neu booten.

## startup/shutdown Skript für co2mini_server

Dieses Script 

https://github.com/jliebich/RaspberryPiNotes/blob/master/scripts/co2mini

installieren, z.B. mit

        cd /etc/init.d/
        wget https://raw.githubusercontent.com/jliebich/RaspberryPiNotes/master/scripts/co2mini
        chmod +x co2mini
        
Jetzt die Variablen file und port darin entsprechend anpassen.
Bei mir sieht es so aus:

        #!/bin/sh
        ### BEGIN INIT INFO
        # Provides:          co2mini server
        # Required-Start:    $all
        # Required-Stop:     
        # Default-Start:     2 3 4 5
        # Default-Stop:      0 1 6
        # Short-Description: 
        # Description:       
        ### END INIT INFO

        file="/home/pi/co2mini/fhem-co2mini/co2mini_server.pl"
        port=20000
        ...

Dann weiter:

        update-rc.d co2mini defaults
        service co2mini start
        
Prüfen ob service korrekt gestartet wurde.
 
        service co2mini status
  
  Muss melden
  
        ...
        Active: active (running) since...
        ...
    
Nach einem Reboot wird der co2mini_server.pl jetzt immer automatisch gestartet.
 
## Installation in FHEM

Auf den anderen Raspi, auf dem FHEM läuft, die Datei 38_co2mini.pm in den Ordner /opt/fhem/FHEM kopieren
In der FHEM Kommandozeile folgendes eingeben:

        reload 38_co2mini

Jetzt das device in FHEM anlegen (IP-Adress und Port ggf. an eigene Gegebenheiten anpassen):

        define co2 co2mini 192.168.0.36:20000

Als readings bekommt man jetzt die CO2 und Temperaturwerte angezeigt

![Readings](https://github.com/jliebich/RaspberryPiNotes/blob/master/bilder/Co2_Readings.PNG)

Jetzt noch ein Log-File anlegen.
In der FHEM Kommandozeile folgendes eingeben:

        define co2_Log FileLog ./log/CO2-%Y-%m.log co2

Inhalt sieht dann so aus:

        ...
        2018-01-20_17:09:53 co2 temperature: 20.35
        2018-01-20_17:09:55 co2 co2: 1361
        2018-01-20_17:09:58 co2 temperature: 20.35
        2018-01-20_17:10:00 co2 co2: 1360
        2018-01-20_17:10:03 co2 temperature: 20.35
        2018-01-20_17:10:05 co2 co2: 1360
        ...

Ui, das sind alle 5 Sekunden eine neue Temperatur und ein neuer CO2-Wert.
Damit das log-File nicht zu groß wird, habe ich noch folgende Attribute gesetzt:

![Attributes](https://github.com/jliebich/RaspberryPiNotes/blob/master/bilder/co2Attributes.PNG)

Jetzt noch einen Plot erstellen

![CO2-Plot-Settings](https://github.com/jliebich/RaspberryPiNotes/blob/master/bilder/co2plotSettings.PNG)

Ergebnis:

![CO2-Plot](https://github.com/jliebich/RaspberryPiNotes/blob/master/bilder/co2plot.PNG)

Man sieht - kurz vor 21 Uhr gelüftet ;-)
