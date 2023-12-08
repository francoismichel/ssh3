# SSH3: faster and rich secure shell using HTTP/3
SSH3 is a complete revisit of the SSH
protocol, mapping its semantics on top of the HTTP mechanisms.
In a nutshell, SSH3 uses QUIC+TLS1.3 for
secure channel establishment and the HTTP Authorization mechanisms for user authentication.
Among others, SSH3 allows the following improvements:
- Significantly faster session establishment
- New HTTP authentication methods such as OAuth 2.0 and OpenID Connect in addition to classical passwords and pubkey authentication
- Robustness to port scanning attacks: your SSH3 server can be made **invisible** to other Internet users
- UDP port forwarding in addition to classical TCP port forwarding
- All the features allowed by the modern QUIC protocol: including connection migration (soon) and multipath connections

*SSH3* stands for the concatenation of *SSH* and *H3*. 

## ⚡ SSH3 is faster
SSH3 offers a significantly faster session establishment than SSHv2. Running a single command with SSHv2 can take between 8 and 6 network round-trips, which can easily be noticed by the user. SSH3 only needs 3 round-trips. On a connection with 50 milliseconds of ping, this reduces the session establishment time from 400 with SSHv2 to 150ms with SSH3. The keystroke latency during a running session is unchanged.


## 🔒 SSH3 is secure
While SSHv2 defines its own protocols for user authentication and secure channel establishment, SSH3 relies on the robust and time-tested mechanisms of TLS 1.3, QUIC and HTTP. These protocols are already extensively used to secure security-critical applications on the Internet such as e-commerce and Internet banking.

**SSH3 already implements the common password-based and public-key (RSA and EdDSA/ed25519) authentication methods.** It also allows new authentication method 
such as OAuth 2.0 and allows logging in to your servers using your Google/Microsoft/Github accounts.

## 🥷 Your SSH3 public server can be hidden
Using SSH3, you can avoid the usual stress of scanning and dictionnary attacks against your SSH server. Similarly to your secret Google Drive documents, your SSH3 server can be hidden behind a secret link and only answer to authentication attempts that made an HTTP request to this specific link, like the following:

    ssh3-server -bind 192.0.2.0:443 -url-path <my-long-secret>

By replacing `<my-long-secret>` by, let's say, the value `M3MzkxYWMxMjYxMjc5YzJkODZiMTAyMjU`, your SSH3 server will only answer to SSH3 connection attempts made to the URL `https://192.0.2.0:443/M3MzkxYWMxMjYxMjc5YzJkODZiMTAyMjU` and it will respond a `404 Not Found` to other requests. Attackers and crawlers on the Internet can therefore not detect the presence of your SSH3 server. It will only see a simple web server answering 404 status codes to every request.

## 💐 SSH3 is already features-rich
SSH3 provides new feature that could not be provided by the SSHv2 protocol.

### Brand new features
- **UDP port forwarding**: you can now access your QUIC, DNS, RTP or any UDP-based server that are only reachable from your SSH3 host.
UDP packets are forwarded using QUIC datagrams.
- **X.509 certificates**: you can now use your classical HTTPS cerificates to authenticate your SSH3 server. This mechanism is more secure than the classical SSHv2 host key mechanism. Certificates can be obtained easily using LetsEncrypt for instance.
- **Hiding** your server behind a secret link.
- **Keyless** secure user authentication using **OpenID Connect**. You can connect to your SSH3 server using the SSO of your company or your Google/Github account, and you don't need to copy the public keys of your users anymore.

### Famous OpenSSH features implemented
This SSH3 implementation already provides many of the popular features of OpenSSH, so if you are used to OpenSSH, so the process of adopting SSH3 will be smooth. Here is a list of OpenSSH features that SSH3 also implements:
- Parses `~/.ssh/authorized_keys` on the server
- Parses `~/.ssh/config` on the client and handles the `Hostname`, `User`, `Port` and `IdentityFile` config options (the other are currently ignored)
- Certificate-based server authentication
- `known_hosts` mechanism when X.509 certificates are not used.
- Automatically using the `ssh-agent` for public key authentication
- SSH agent forwarding to use your local keys on your remote server
- Direct TCP port forwarding (reverse port forwarding will be implemented in the future)

