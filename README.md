```I```

    Собрать информацию об ip цели - местоположение, домены и т.д (Сеть, поддомены и сбор ключевой информации)
    Применить фильтр по ip чтобы увидеть какие домены прикреплены к данному ip
    Нахождение всех доступных файлов, директорий, контактной информации, местонахождение, CMS, диапазон IP адресов
    Далее - nslookup
    Далее - dig
    Далее - связывающие узлы trace 

```II```

    Находим сервисы, которые будем тестировать, nmap
    Сервисы (http/https, FTP, Telnet, ssh, Веб-камеры, Smb, DNS ...)
    Нахождение открытых портов, dns записях, активных хостах, ОС системы, версии ПО
    
    Версий ОС и ПО
        nmap example.com -sV -A -v -O
    Активные хосты
        fping -Asg 95.213.8.0/24 -r 3 >> ip.lst
        cat ip.lst | grep alive
    DNS
        * NS записи - показывают какие DNS обслуживают данную зону.
        * MX записи - определяют почтовые серверы обслуживающие данную зону.
            * nslookup
                > set q=ns
                > site.com
            * nslookup
                > q=mx
                > site.com

```III```

    Изучить логику веб-приложения
    Смотреть мобильные приложения и API

---

**Validators, generators and converters**
https://mothereff.in/

---
**Мониторинг dns запросов - dnschef**
http://thesprawl.org/projects/dnschef/

dig, nslookup, mxtoolbox.com

---

***Plugins***

**Wappalyzer**
https://chrome.google.com/webstore/detail/wappalyzer/gppongmhjkpfnbhagpmjfkannfbllamg?hl=ru

**User Agent Switcher** - подмена user agent
https://chrome.google.com/webstore/detail/user-agent-switcher-for-c/djflhoibgkdhkhhcedjiklpkjnoahfmg

**EditThisCookie** - работа с куками
https://chrome.google.com/webstore/detail/editthiscookie/fngmhnnpilhplaeedifhccceomclgfbg?hl=ru

**Hackbar** - помогает тестировать простые SQL-инъекции и XSS-дырки
https://chrome.google.com/webstore/detail/hackbar/ejljggkpbkchhfcplgpaegmbfhenekdc

**Proxy SwitchySharp**
https://chrome.google.com/webstore/detail/proxy-switchysharp/dpplabbmogkhghncfbfdeeokoefdjegm/details

**IP Address and Domain Information**
https://chrome.google.com/webstore/detail/ip-address-and-domain-inf/lhgkegeccnckoiliokondpaaalbhafoa

---

**Recon-ng** - разведывательный веб-фреймворк, предназначен для обнаружения поддоменов, файлов с приватными данными, перебора пользователей, парсинга соцсетей, и т.д.
https://bitbucket.org/LaNMaSteR53/recon-ng?_gclid=5b7836c321d675.57052296-5b7836c321d738.64652729&_utm_source=xakep&_utm_campaign=mention48838&_utm_medium=inline&_utm_content=lnk245832910320
https://www.youtube.com/watch?time_continue=3&v=PcWWsNgXtLg

**IPV4info** - сайт позволяет найти домены, которые размещены на указанном сервере.
http://ipv4info.ru/

**Nmap** - предназначен для сканирования сетей и аудита безопасности.

https://nmap.org/man/ru/index.html

https://codeby.net/kniga-po-nmap-na-russkom/

https://habr.com/post/88064/

**Nikto** - сканер веб-серверов, который тестирует серверы и сервисы на многие уязвимости.
• Потенциально опасные файлы/программы
• Устаревшие версии серверов
• Специфичные проблемы и особенности каких-либо версий используемого ПО
• Проверка конфигурации сервера

https://cirt.net/nikto2

**Burp Suite** - перехватчик прокси, который позволяет просматривать и изменять трафик, паук для краулинга сбора контента и манипуляций с ним, веб-сканер для автоматизации обнаружения уязвимостей, ретранслятор для манипулирования и переотправки индивидуальных запросов, повторитель для тестирования случайных токенов, инструмент для сравнения запросов и ответов.

https://portswigger.net/burp

https://vimeo.com/album/3510171

https://habr.com/company/pentestit/blog/328382/

_Burp Suite scanner plugin_
https://github.com/vulnersCom/burp-vulners-scanner

**Fiddler** - работа с трафиком, позволяет устанавливать контрольные точки и «скрипку» с входящими или исходящими данными.

https://www.telerik.com/fiddler

https://habr.com/post/140147/

**Sqlmap** - позволяет тестировать сайты на SQLi (SQL Injection) с огромным списком возможностей.

http://sqlmap.org/

https://hackware.ru/?p=1928

**Bucket Finder** - инструмент, который позволит искать бакеты Amazon S3, доступные на чтение и покажет все файлы в них. Это также может быть использовано для быстрого поиска бакетов, которые существуют, но не позволяют прочитать список файлов - на этих бакетах вы можете воспользоваться AWS CLI для проверки доступа на запись.

https://digi.ninja/projects/bucket_finder.php

**Wireshark** - анализатор сетевого протокола, который позволяет увидеть что происходит с сетью в мельчайших подробностях.

https://www.wireshark.com/

https://habr.com/post/204274/

**ProtonMail** - сервис веб-почты с шифрованием
https://protonmail.com/

**Mozilla thunderbird** + **TorBirdy** -  бесплатная почтовая программа и плагин

https://www.thunderbird.net/en-US/
https://addons.thunderbird.net/en-us/thunderbird/addon/torbirdy/?_gclid=5b830275655ad2.33569197-5b830275655b69.27001638&_utm_source=xakep&_utm_campaign=mention103074&_utm_medium=inline&_utm_content=lnk518837409360?_gclid=5b830275655ad2.33569197-5b830275655b69.27001638&_utm_source=xakep&_utm_campaign=mention103074&_utm_medium=inline&_utm_content=lnk518837409360

**DuckDuckGo** - поисковик

https://duckduckgo.com/

https://chrome.google.com/webstore/detail/duckduckgo-home-page/ljkalbbbffedallekgkdheknngopfhif

**Tor** - система прокси-серверов
https://www.torproject.org/

**John the Ripper and THC-Hydra** - bruteforce

http://www.openwall.com/john/

https://github.com/vanhauser-thc/thc-hydra

---

**Subdomains:**

https://www.whois.com/

http://www.wolframalpha.com

http://searchdns.netcraft.com/

https://www.virustotal.com/#/domain/domain.com

https://github.com/TheRook/subbrute

https://github.com/aboul3la/Sublist3r

https://github.com/antichown/subdomain-takeover

https://github.com/nahamsec/HostileSubBruteforcer (ruby)

https://github.com/subfinder/subfinder (go)

https://toolbox.googleapps.com/apps/dig/ (CNAME)

_other tools for domains_

https://github.com/michenriksen/aquatone

https://github.com/mhmdiaa/second-order

https://github.com/guelfoweb/knock

https://github.com/random-robbie/bugbounty-scans

https://crt.sh/?q=%25domain.com

https://censys.io/

Subdomain takeover with Shopify, Heroku and something more …
https://medium.com/@valeriyshevchenko/subdomain-takeover-with-shopify-heroku-and-something-more-6e9504da34a1


Amazon Cloudfront | Heroku | Desk.com | Pantheon service | Github Pages

---------------------------------------------------------------------------

**Photon** - инструмент, который извлекает URL-адреса, электронные письма, файлы, учетные записи веб-сайтов и многое другое
https://github.com/s0md3v/Photon

**Striker** - это сборщик информации и сканер уязвимостей
https://github.com/s0md3v/Striker

---------------------------------------------------------------------------

**CURL**

`получаем содержания главной страницы:`
curl http://example.com	

`получаем содержания главной страницы в файл index.html:`
curl -o index.html http://example.com	

`получаем http-заголовки с сайта:`
curl -I proft.me	

`подменить домен при обращении к серверу (передача своего заголовка):`
curl -H 'Host: google.ru' http://example.com	

`при получении содержимого страницы следовать по редиректам (если такие есть):`
curl -L http://example.com	

`получение страницы скрытой за Basic HTTP Authentication:`
curl -u username:password http://example.com/login/	

`получение страницы используя прокси:`
curl -x proxy.com:3128 http://example.com	

`распарсить сайт, получение ссылок:`
curl -s http://example.com |egrep -o 'href\=\"/[a-zA-Z0-9\/]+\"'

`Чтобы изменить referer нужно воспользоваться ключом "-e" и указать нужный URL:`
curl -e google.com -X GET http://example.com/Content/Challenges/Web/Web4

`передача данных POST-запросом:`
curl --request POST "http://example.com/form/" --data "field1=value1&field2=value2"	

`передача данных POST-запросом:`
curl -X POST "http://example.com/form/" --data "field1=value1&field2=value2"	

`передача данных POST-запросом, данные в виде JSON:`
curl -X POST -H "Content-Type: application/json" -d '"title":"Commando","year":"1985"' http://example.com/api/movies/	

`передача данных PUT-запросом:`
curl --request PUT "http://example.com/api/movie/1/" --data "title=DjangoUnchained"	

`сохранить полученные Cookie в файл используйте опцию -c:`
curl -c cookie.txt http://example.com/post.php

`отправить cookie curl обратно:`
curl -b cookie.txt http://example.com/post.php/	

`отправку файлов на ftp сервер:`
curl -T login.txt ftp://sub.example.com/upload/

`проверить отправку файла по HTTP:`
curl -T ~/login.txt http://example.com/post.php

---

**Exploit database**
https://www.exploit-db.com

---

**Google Dorks**
https://habr.com/post/283210/

https://telegra.ph/Google-kak-sredstvo-vzloma-Razbiraem-aktualnye-recepty-Google-Dork-Queries-09-23

site:example.com filetype:txt

inurl - ищет текст в url'е сайта

intitle - ищет текст в заголовке сайта

intext - поиск в теле страницы

---
**Дополнительный материал:**

Owasp.org

Hackerone.com/hacktivity

Twitter #infsec

https://github.com/jhaddix/tbhm

https://www.reddit.com/r/ReverseEngineering/

https://forum.reverse4you.org/showthread.php?t=2656
