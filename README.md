
<div align=center>
<img src="resources/figures/ssh3.png" style="display: block; width: 60%">
</div>


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
Faster for session establishment, not throughput ! SSH3 offers a significantly faster session establishment than SSHv2. Establishing a new session with SSHv2 can take 5 to 7 network round-trips, which can easily be noticed by the user. SSH3 only needs 3 round-trips. The keystroke latency in a running session is unchanged.

![](resources/figures/ssh3_100ms_rtt.gif)
*SSH3 (top) VS SSHv2 (bottom) session establishement with a 100ms ping towards the server.*

## 🔒 SSH3 is secure
While SSHv2 defines its own protocols for user authentication and secure channel establishment, SSH3 relies on the robust and time-tested mechanisms of TLS 1.3, QUIC and HTTP. These protocols are already extensively used to secure security-critical applications on the Internet such as e-commerce and Internet banking.

SSH3 already implements the common password-based and public-key (RSA and EdDSA/ed25519) authentication methods.
It also allows new authentication method 
such as OAuth 2.0 and allows logging in to your servers using your Google/Microsoft/Github accounts.

## 🥷 Your SSH3 public server can be hidden
Using SSH3, you can avoid the usual stress of scanning and dictionnary attacks against your SSH server. Similarly to your secret Google Drive documents, your SSH3 server can be hidden behind a secret link and only answer to authentication attempts that made an HTTP request to this specific link, like the following:

    ssh3-server -bind 192.0.2.0:443 -url-path <my-long-secret>

By replacing `<my-long-secret>` by, let's say, the random value `M3MzkxYWMxMjYxMjc5YzJkODZiMTAyMjU`, your SSH3 server will only answer to SSH3 connection attempts made to the URL `https://192.0.2.0:443/M3MzkxYWMxMjYxMjc5YzJkODZiMTAyMjU` and it will respond a `404 Not Found` to other requests. Attackers and crawlers on the Internet can therefore not detect the presence of your SSH3 server. It will only see a simple web server answering 404 status codes to every request.

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

## Installing SSH3
You can either download one of the release binaries or compile the code from source.

### Compiling SSH3 from source
You need a recent Golang version to do this.
Downloading the source code and compiling the binaries can be done with the following steps:

```bash
git clone https://github.com/francoismichel/ssh3    # clone the repo
cd ssh3
go build -o ssh3 client/main.go                     # build the client
go build -o ssh3-server server/main.go              # build the server
```

If you have root/sudo priviledges and you want to make ssh3 accessible to all you users,
you can then directly copy the binaries to `/usr/bin`:

```bash
cp ssh3 /usr/bin/ && cp ssh3-server /usr/bin
``` 

Otherwise, you can simply add the executables to your `PATH` environment variable by adding
the following line at the end of your `.bashrc` or equivalent:

```bash
export PATH=$PATH:/path/to/the/ssh3/directory
```

### Deploying an SSH3 server
Before connecting to your host, you need to deploy an SSH3 server on it. There is currently
no SSH3 daemon, so right now, you will have to run the `ssh3-server` executable in background
using `screen` or a similar utility.


> [!NOTE]  
> As SSH3 runs on top of HTTP/3, a server needs a valid X.509 certificate and its corresponding
> private key to work. If you do not want to generate a certificate signed by a real public
> certificate authority, you can generate a self-signed certificate using the
> `generate_openssl_selfsigned_certificate.sh` script available in this repository.
> This should provide you with similar security guarantees to SSHv2's classical
> host keys mechanism, with the same security issue: you may be vulnerable to
> machine-in-the-middle attacks during your first connection to your server.
> Using real certificates signed by public certificate authorities such as Let's Encrypt
> avoids this security issue.


Here is the usage of the `ssh3-server` executable:

```
Usage of ./ssh3-server:
  -bind string
        the address:port pair to listen to, e.g. 0.0.0.0:443 (default "[::]:443")
  -cert string
        the filename of the server certificate (or fullchain) (default "./cert.pem")
  -enable-password-login
        if set, enable password authentication (disabled by default)
  -key string
        the filename of the certificate private key (default "./priv.key")
  -url-path string
        the secret URL path on which the ssh3 server listens (default "/ssh3-term")
  -v    verbose mode, if set
```