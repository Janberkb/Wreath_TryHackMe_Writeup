# Wreath Network Pentest Report: https://www.notion.so/janberknotes/Wreath-Network-Pentest-Report-13f3633271b04773a86b01bfb7853541

📡 **[https://tryhackme.com/room/wreath](https://tryhackme.com/room/wreath)**

## Network Analysis

- There are three machines on the network
- There is public facing webserver
- There is self hosted git server on network
- There is a pc running on the network that has antivirus installed (probably windows)
- Windows PC cannot be accessed directly from public facing webserver (Check this)

# 1-)Enumeration - Nmap Scan on 10.200.99.200

## Nmap Scan Includes

- TCP  SYN Scan
- Service Version Detection on Ports
- Nmap Discovery Script
- Port range 0-15000

## Scan Results Summary

- There is 4 ports open and 1 port closed. (Click triangle to expand.)
    - 22/tcp open ssh OpenSSH 8.0 (Protocol 2.0)
    - 80/tcp open http Apache httpd 2.4.37 ((centos) OpenSSL/1.1.1c)
    - 443/tcp open ssl/http Apache httpd 2.4.37 ((centos) OpenSSL/1.1.1c)
    - 9090/tcp closed zeus-admin
    - 10000/tcp open http MiniServ 1.890 (Webmin httpd)
- Web Server is running on centos and published on Apache Server.
- Domain name is "thomaswreath.thm"
- There is an e-mail in website. (me@thomaswreath.thm)
- There is an admin panel on port 10000

### Scan Output

[Nmap Scan On 10.200.99.200](Wreath%20Network%20Pentest%20Report%2013f3633271b04773a86b01bfb7853541/Nmap%20Scan%20On%2010%20200%2099%20200%2019469fc487994b4d91302d0e2255d2ae.md)

# 2-)Enumeration - Checking Services

- Found a website on 80/443 ports. (DNS is not configured, need to add the domain name in /etc/hosts file.)
- Found a website admin panel which is vulnerable (Webmin 1.890).
- As we can see below, this vulnerability is available for 1.890 too.
- (Just searched "webmin 1.890 vulnerability")

![Wreath%20Network%20Pentest%20Report%2013f3633271b04773a86b01bfb7853541/Untitled.png](Wreath%20Network%20Pentest%20Report%2013f3633271b04773a86b01bfb7853541/Untitled.png)

- It is possible to exploit with remote command execution vulnerabilities.

# 3-)Finding Vulnerabilities and Exploiting

- I wanted to check python exploits first because I think this is easier.

![Wreath%20Network%20Pentest%20Report%2013f3633271b04773a86b01bfb7853541/Untitled%201.png](Wreath%20Network%20Pentest%20Report%2013f3633271b04773a86b01bfb7853541/Untitled%201.png)

- There is lots of github repo, let's check the [first](https://github.com/jas502n/CVE-2019-15107) of them.
- It looks like it can execute linux commands as root user. This means we can do everything inside.
- This means we can use this command to create reverse shell of course.
- We can check files like this either but it is not comfortable, but we can.

![Wreath%20Network%20Pentest%20Report%2013f3633271b04773a86b01bfb7853541/Untitled%202.png](Wreath%20Network%20Pentest%20Report%2013f3633271b04773a86b01bfb7853541/Untitled%202.png)

- There is another python file that can create reverse shell and connect us. That's what I was looking for.
- [CVE-2019-15107](https://github.com/MuirlandOracle/CVE-2019-15107)

![Wreath%20Network%20Pentest%20Report%2013f3633271b04773a86b01bfb7853541/Untitled%203.png](Wreath%20Network%20Pentest%20Report%2013f3633271b04773a86b01bfb7853541/Untitled%203.png)

- Found id_rsa file including ssh authentication key and connected on ssh.

![Wreath%20Network%20Pentest%20Report%2013f3633271b04773a86b01bfb7853541/Untitled%204.png](Wreath%20Network%20Pentest%20Report%2013f3633271b04773a86b01bfb7853541/Untitled%204.png)

- Exploiting done and no need to escelation anymore because we connected as root.

# 4-)Pivoting

> Pivoting is accessing other machines over one machine in the network and getting deeper. After accessing the public-faced server, you can access other machines by using some technics.

- Sources: [Turkish](https://www.bgasecurity.com/2012/02/pentest-calsmalarnda-network-pivoting/) / [English](https://www.geeksforgeeks.org/pivoting-moving-inside-a-network/)

[Notes](Wreath%20Network%20Pentest%20Report%2013f3633271b04773a86b01bfb7853541/Notes%204c889d4d7e7b42d885caa6091dc37dfe.md)

### For example:

![Wreath%20Network%20Pentest%20Report%2013f3633271b04773a86b01bfb7853541/Untitled%205.png](Wreath%20Network%20Pentest%20Report%2013f3633271b04773a86b01bfb7853541/Untitled%205.png)

## Enumeration

> Enumeration is collecting information and learning what type of structure in front of us. What methods can we use?

### ifconfig

> ifconfig command shows us interfaces information, this means how many interface machine has, what is it's IP, gateway(probably). We have connected the machine on ssh. run this command and see.

![Wreath%20Network%20Pentest%20Report%2013f3633271b04773a86b01bfb7853541/Untitled%206.png](Wreath%20Network%20Pentest%20Report%2013f3633271b04773a86b01bfb7853541/Untitled%206.png)

> We have one ethernet interface named "eth0", nothing else.

> When I research pivoting and enumeration technics, I see **arp -a** command.

### arp -a

> Arp table is a table that holds IP addresses and mac addresses to know what IP address is owned by who. When I look into the table I can see how many machines communicating with this machine and what is their mac addresses and IPs. So run this command.

![Wreath%20Network%20Pentest%20Report%2013f3633271b04773a86b01bfb7853541/Untitled%207.png](Wreath%20Network%20Pentest%20Report%2013f3633271b04773a86b01bfb7853541/Untitled%207.png)

> I can see that two machines are communicating with this machine recently. 10.200.99.1 probably is the gateway. The second machine could be the git server because he said there is a local git server that can update the website with his command.

### Checking resolv.conf file

> resolv.conf file holds DNS settings, if you can see "nameserver" and IP next to it, it means this IP is the DNS.

DNS holds name addresses of IPs. Instead of writing an IP of a website or machine, if you have a DNS server you can use, you can write just this machine's name, the system automatically recognizes the IP from the name. (Example: "google.com" is a domain name)

### Scanning with Nmap

If you want to scan with Nmap on ssh and it is not installed on that machine, you can copy  the portable version of Nmap to the remote machine using this command:

```bash
scp <-i key_file> <Local File Location> <user@remote_machine_IP:location_to_copy>
-i: Authorization key (If you don't have that and you have a password don't write it)
scp -i id_rsa nmap-portable.zip root@10.200.99.200:/root/
```

```bash
Example Nmap Scan:
/root/nmap-portable/run-nmap.sh -sS -sV -O 10.200.99.0/24
```

## Proxychains & Foxyproxy

- Let's see what proxy is and how could we use this for pivoting.

### What is Proxy?

> In the simplest terms for example, when you want to access somewhere like a website, you are asking someone to access this website, if you don't have access to this website and "someone" has access, it accesses this website and shows this website to you. Your IP is hidden because you are not accessing that website, you are just asking someone and it is accessing, so the website can not detect that you are seeing that.

For more and technically information visit [here.](https://www.varonis.com/blog/what-is-a-proxy-server/)

### Proxychains

> We can use this tool for sending requests through the IP and Port that we want. You can read [this](https://linuxhint.com/proxychains-tutorial/) to know how to use and configure. For example:

- If we have this type of configuration "socks4 127.0.0.1 4242" when I send a request or packet while using proxychains, the packet will be sent from this Host and Port.
- If I want to connect somewhere over telnet through proxy I can use that command;

```jsx
proxychains telnet 172.16.0.100 23
```

- This telnet request will be sent from my IP and 4242 port to 172.16.0.100.

### Foxyproxy

> This is a web browser extension and if we need proxy for accessing webserver we can use this.

## SSH Tunnelling / Port Forwarding

> SSH Tunnelling is creating a tunnel by using ssh connection. If you have an SSH connection to the machine that you are attacking, you can create a tunnel there and you can access everywhere in that network that it can.

![Wreath%20Network%20Pentest%20Report%2013f3633271b04773a86b01bfb7853541/Untitled%208.png](Wreath%20Network%20Pentest%20Report%2013f3633271b04773a86b01bfb7853541/Untitled%208.png)

 For more information visit [here](https://www.tunnelsup.com/how-to-create-ssh-tunnels/).

> Basically, if we can not access that green server above, we ask the red server to access green and show us. This is like an exact tunnel. If you can not get inside, you can dig a tunnel to get inside 😉

### Let's create SSH Tunnel for example

 

```bash
Imagine that we have Blue Server above and we don't have access to Green Servers
Web Server but we want to access that Web Server.
We have an SSH connection to Red Server and Red Server has access to Green Servers
Web Server. Let's dig a tunnel to Red Server to access Green Server.
We can forward our 8080 port to 192.168.0.3:80 through 192.168.0.2

ssh -L 8080:192.168.0.3:80 user@192.168.0.2 -Fn
ssh -L <local_port_that_we_forward>:<The_server_IP_that_we_want_to_access>:<port> <username_for_ssh_connection>@<IP> -Fn
-L:Local Port Forwarding
-Fn:Establish that connection background and don't execute command
```

> Of course, we can create SSH Proxy Tunnel either. If we do that we don't need to connect just one port, we can use this proxy connection with FoxyProxy to access the webserver, we can use proxychains tool to execute some other commands.

```bash
If you use that command you can set your proxy configuration to localhost:1337 and access everywhere from SSH server.

ssh -D 1337 user@192.168.0.2 -fN
```
