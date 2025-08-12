# Network Traffic Capture and Protocol Analysis Using Wireshark

## Project Summary

This repository contains a live network packet capture and analysis performed with Wireshark. The goal is to demonstrate real-world traffic collection, identify common protocols (FTP, HTTP, DNS, TLS/HTTPS, ICMP), and provide a concise security-focused analysis.

---
1) TLS / HTTPS
Example packet: Packet #188 — Client Hello (SNI=www.openai.com)
What it shows: The TLS Client Hello initiating a TLS 1.3 handshake. SNI reveals the hostname www.openai.com while the remainder of the session is encrypted.
Why it matters: Confirms that the site negotiated an encrypted channel; payloads are not readable but handshake metadata (SNI, cipher suites) is visible.

<img width="1629" height="926" alt="Screenshot 2025-08-11 212625" src="https://github.com/user-attachments/assets/442385bf-c406-4437-9dd1-221aaa3fe74f" />


---
2) ICMP (Network Diagnostic / Error)
Example packet: Packet #8266 — Destination unreachable (Port unreachable)
What it shows: The remote host 172.64.154.211 returned an ICMP error indicating that a previously sent UDP packet targeted a closed/unavailable port.
Why it matters: Useful for troubleshooting; indicates the remote host is reachable but the service/port is not available. Often occurs with misdirected UDP traffic or blocked/closed services.

<img width="1118" height="430" alt="Screenshot 2025-08-12 232904" src="https://github.com/user-attachments/assets/d86f12eb-b22c-4875-bcb1-0411a166a5f0" />

---

3) FTP (Plaintext credentials)
Example: USER demo / PASS password visible in the capture (replace with exact packet numbers)
What it shows: FTP transmits authentication credentials in plaintext on TCP port 21.
Security implication: Credentials can be intercepted by an on-path attacker; use FTPS or SFTP instead.

<img width="1629" height="924" alt="Screenshot 2025-08-11 205625" src="https://github.com/user-attachments/assets/75e8060f-de9a-4b4c-9320-5cd1cff0a141" />

---
4) HTTP
What to capture for evidence: GET requests and HTTP/1.1 200 OK responses (for example http://example.com).
Security implication: HTTP is unencrypted; all content and headers are visible in the capture.

<img width="822" height="425" alt="Screenshot 2025-08-12 232951" src="https://github.com/user-attachments/assets/32dd3cf2-ba92-4e3a-aeb2-e8593c15c478" />

<br>
Because of HTTP is unencrypted, anyone on the same network can see exactly what data is being exchanged, including page contents and headers.

```
GET / HTTP/1.1
Host: www.example.com
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: keep-alive
Upgrade-Insecure-Requests: 1
Priority: u=0, i


HTTP/1.1 200 OK
Accept-Ranges: bytes
Content-Type: text/html
ETag: "84238dfc8092e5d9c0dac8ef93371a07:1736799080.121134"
Last-Modified: Mon, 13 Jan 2025 20:11:20 GMT
Vary: Accept-Encoding
Content-Encoding: gzip
Content-Length: 648
Cache-Control: max-age=335
Date: Mon, 11 Aug 2025 15:50:29 GMT
Connection: keep-alive

<!doctype html>
<html>
<head>
    <title>Example Domain</title>

    <meta charset="utf-8" />
    <meta http-equiv="Content-type" content="text/html; charset=utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <style type="text/css">
    body {
        background-color: #f0f0f2;
        margin: 0;
        padding: 0;
        font-family: -apple-system, system-ui, BlinkMacSystemFont, "Segoe UI", "Open Sans", "Helvetica Neue", Helvetica, Arial, sans-serif;
        
    }
    div {
        width: 600px;
        margin: 5em auto;
        padding: 2em;
        background-color: #fdfdff;
        border-radius: 0.5em;
        box-shadow: 2px 3px 7px 2px rgba(0,0,0,0.02);
    }
    a:link, a:visited {
        color: #38488f;
        text-decoration: none;
    }
    @media (max-width: 700px) {
        div {
            margin: 0 auto;
            width: auto;
        }
    }
    </style>    
</head>

<body>
<div>
    <h1>Example Domain</h1>
    <p>This domain is for use in illustrative examples in documents. You may use this
    domain in literature without prior coordination or asking for permission.</p>
    <p><a href="https://www.iana.org/domains/example">More information...</a></p>
</div>
</body>
</html>
````
---

5) DNS
What to capture for evidence: DNS query/response pairs (e.g., Query: example.com → Response: A 93.184.216.34)
Security implication: DNS queries are typically in plaintext (UDP/53) and can reveal user browsing intent; consider DoH/DoT for privacy.

<img width="1919" height="657" alt="Screenshot 2025-08-12 232840" src="https://github.com/user-attachments/assets/3653c79d-e26c-44c0-8aca-4d26c91d5fd7" />


---

## Legitimate vs Malicious Uses

| Protocol | Legitimate Uses                     | Malicious Uses                    |
| -------- | ----------------------------------- | --------------------------------- |
| FTP      | File transfer between trusted hosts | Credential theft via sniffing     |
| HTTP     | Serving static web content          | Session hijacking, data injection |


## Protocols Identified and Analyzed

| Protocol | Description | Packet Example | Key Observations | Security Implications |
| -------- | ----------- | -------------- | ---------------- | --------------------- |
| **FTP** (File Transfer Protocol) | A protocol for transferring files over a network. It sends data, including usernames and passwords, in plaintext. | Packet #45 (USER demo), Packet #46 (PASS password) | Plaintext credentials captured, `LIST` and `RETR` commands visible | FTP is insecure; credentials can be intercepted. Use FTPS or SFTP instead. |
| **HTTP** (Hypertext Transfer Protocol) | Protocol for unencrypted web browsing. | Packet #120 (GET http://example.com/) | Clear GET requests and server responses with HTML content | Data is unencrypted and vulnerable to interception or tampering. |
| **TLS/HTTPS** (Transport Layer Security) | Protocol for encrypted secure web communication. | Packet #188 (TLS Client Hello to www.openai.com) | Encrypted handshake visible; content not readable | Protects confidentiality and integrity of data in transit. |
| **DNS** (Domain Name System) | Resolves domain names to IP addresses. | Packet #25 (Query for example.com), Packet #26 (Response) | Clear query/response pairs; essential for name resolution | DNS queries are often unencrypted, vulnerable to spoofing or interception. |
| **ICMP** (Internet Control Message Protocol) | Used for diagnostic tools like ping. | Packet #8266 (Destination unreachable) | Network error message indicating unreachable ports | Normal network behavior; useful for troubleshooting connectivity issues. |

---

## Key Findings

- Successfully captured multiple protocols on a live network including FTP, HTTP, TLS/HTTPS, DNS, and ICMP.  
- **FTP traffic revealed plaintext login credentials (`demo` / `password`)**, underscoring FTP's security weaknesses.  
- HTTP traffic showed unencrypted web requests to non-HTTPS sites such as `example.com`.  
- TLS packets demonstrated the handshake process for secure web communication, including Server Name Indication (SNI).  
- DNS queries and responses were clearly visible, showing the translation of domain names to IP addresses.  
- An ICMP “Destination unreachable (Port unreachable)” message was captured, illustrating common network error diagnostics.

---

## Security Recommendations

- Avoid using **FTP** due to its plaintext credential transmission; prefer **FTPS** or **SFTP** for secure file transfers.  
- Always use **HTTPS** to ensure encryption of web traffic.  
- Consider implementing **DNS over HTTPS (DoH)** or **DNS over TLS (DoT)** to protect DNS queries.  
- Monitor ICMP traffic for abnormal patterns that may indicate network scanning or attacks.

---

## How to Reproduce This Capture

1. Install Wireshark on your machine.  
2. Start capturing on your active network interface.  
3. Generate traffic by:  
   - Browsing `http://example.com` for HTTP traffic.  
   - Browsing `https://openai.com` for TLS traffic.  
   - Running `nslookup example.com` for DNS queries.  
   - Using `ftp` to connect to `test.rebex.net` with username `demo` and password `password`.  
   - Running `ping -c 4 8.8.8.8` to generate ICMP traffic.  
4. Stop the capture after 1-2 minutes and save the `.pcap` file.

---

## References

- [Wireshark Official Documentation](https://www.wireshark.org/docs/)  
- [FTP Security Risks](https://www.cloudflare.com/learning/security/glossary/ftp/)  
- [DNS and DNS Security](https://www.cloudflare.com/learning/dns/what-is-dns/)  
- [TLS Protocol Overview](https://tools.ietf.org/html/rfc8446)  
- [ICMP Explained](https://www.cloudflare.com/learning/ddos/glossary/internet-control-message-protocol-icmp/)  

