
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
> As SSH3 runs on top of HTTP/3, a server needs an X.509 certificate and its corresponding private key. If you do not want to generate a certificate signed by a real certificate authority, you can generate a self-signed one using the `generate_openssl_selfsigned_certificate.sh` script. This provides you with similar security guarantees to SSHv2's host keys mechanism, with the same security issue: you may be vulnerable to machine-in-the-middle attacks during your first connection to your server. Using real certificates signed by public certificate authorities such as Let's Encrypt avoids this issue.


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

The following command starts a public SSH3 server on port 443 and answers to new
sessions requests querying the `/ssh3` URL path:

    ssh3-server -cert /path/to/cert/or/fullchain -key /path/to/cert/private/key -url-path /ssh3

**Note that, similarly to OpenSSH, the server must be run with root priviledges to log in as other users.**


### Using the SSH3 client
Once you have an SSH3 server running, you can connect to it using the SSH3 client similarly to what
you did with your classical SSHv2 tool.

Here is the usage of the `ssh3` executable:

```
Usage of ssh3:
  -pubkey-for-agent string
        if set, use an agent key whose public key matches the one in the specified path
  -privkey string
        private key file
  -use-password
        if set, do classical password authentication
  -forward-agent
        if set, forwards ssh agent to be used with sshv2 connections on the remote host
  -forward-tcp string
        if set, take a localport/remoteip@remoteport forwarding localhost@localport towards remoteip@remoteport
  -forward-udp string
        if set, take a localport/remoteip@remoteport forwarding localhost@localport towards remoteip@remoteport
  -insecure
        if set, skip server certificate verification
  -keylog string
        Write QUIC TLS keys and master secret in the specified keylog file: only for debugging purpose
  -use-oidc string
        if set, force the use of OpenID Connect with the specified issuer url as parameter
  -oidc-config string
        OpenID Connect json config file containing the "client_id" and "client_secret" fields needed for most identity providers
  -do-pkce
        if set, perform PKCE challenge-response with oidc
  -v    if set, enable verbose mode
```

#### Config-based session establishment
`ssh3` parses your OpenSSH config. Currently, it only handles the `Hostname`; `User`, `Port` and `IdentityFile` options.
Let's say you have the following lines in your OpenSSH config located in `~/.ssh/config` :
```
Host my-server
  HostName 192.0.2.0
  User username
  IdentityFile ~/.ssh/id_rsa
```

Similarly to what OpenSSH does, the following `ssh3` command will connect you to the SSH3 server running on 192.0.2.0 on UDP port 443 using public key authentication with the private key located in `.ssh/id_rsa` :

      ssh3 my-server

If you do not want a config-based utilization of SSH3, yo ucan read the sections below to see how to use the CLI parameters of `ssh3`.

#### Private-key authentication
You can connect to your SSH3 server at my-server.example.org using the private key located in `~/.ssh/id_rsa` with the following command:

      ssh3 -privkey ~/.ssh/id_rsa username@my-server.example.org

#### Agent-based private key authentication
The SSH3 client works with the OpenSSH agent and uses the classical `SSH_AUTH_SOCK` environment variable to
communicate with this agent. Similarly to OpenSSH, SSH3 will list the keys provided by the SSH agent
and connect using the first key listen by the agent by default.
If you want to specify a specific key to use with the agent, you can either specify the private key
directly with the `-privkey` argument like above, or specify the corresponding public key using the
`-pubkey-for-agent` argument. This allows you to authenticate in situations where only the agent has
a direct access to the private key but you only have access to the public key.

#### Password-based authentication
While discouraged, you can connect to your server using passwords (if explicitly enabled on the `ssh3-server`)
with the following command:

      ssh3 -use-password username@my-server.example.org

#### OpenID Connect based authentication.
This feature is still experimental but allows you to connect using an external identity provider such as the one
of your company or any other provider that implements the OpenID Connect standard, such as Google Identity,
Github or Microsoft Entra.
