
<div align=center>
<img src="resources/figures/h3sh.png" style="display: block; width: 60%">
</div>


# H3SH: faster and rich secure shell using HTTP/3
H3SH is a complete revisit of the SSH
protocol, mapping its semantics on top of the HTTP mechanisms.
In a nutshell, H3SH uses [QUIC](https://datatracker.ietf.org/doc/html/rfc9000)+[TLS1.3](https://datatracker.ietf.org/doc/html/rfc8446) for
secure channel establishment and the [HTTP Authorization](https://www.rfc-editor.org/rfc/rfc9110.html#name-authorization) mechanisms for user authentication.
Among others, H3SH allows the following improvements:
- Significantly faster session establishment
- New HTTP authentication methods such as [OAuth 2.0](https://datatracker.ietf.org/doc/html/rfc6749) and [OpenID Connect](https://openid.net/specs/openid-connect-core-1_0.html) in addition to classical SSH authentication
- Robustness to port scanning attacks: your H3SH server can be made **invisible** to other Internet users
- UDP port forwarding in addition to classical TCP port forwarding
- All the features allowed by the modern QUIC protocol: including connection migration (soon) and multipath connections

> [!TIP]
> Quickly want to get started ? Checkout how to [install H3SH](#installing-h3sh). You will learn to [setup an H3SH server](#deploying-an-h3sh-server) and [use the H3SH client](#using-the-h3sh-client).

*H3SH* stands for *HTTP/3* and *shell*.

## ⚡ H3SH is faster
Faster for session establishment, not throughput ! H3SH offers a significantly faster session establishment than SSHv2. Establishing a new session with SSHv2 can take 5 to 7 network round-trip times, which can easily be noticed by the user. H3SH only needs 3 round-trip times. The keystroke latency in a running session is unchanged.

<p align="center">
<img src="resources/figures/h3sh_100ms_rtt.gif"/>
<i>H3SH (top) VS SSHv2 (bottom) session establishement with a 100ms ping towards the server.</i>
</p>

## 🔒 H3SH is secure
While SSHv2 defines its own protocols for user authentication and secure channel establishment, H3SH relies on the robust and time-tested mechanisms of TLS 1.3, QUIC and HTTP. These protocols are already extensively used to secure security-critical applications on the Internet such as e-commerce and Internet banking.

H3SH already implements the common password-based and public-key (RSA and EdDSA/ed25519) authentication methods.
It also supports new authentication methods
such as OAuth 2.0 and allows logging in to your servers using your Google/Microsoft/Github accounts.

## 🥷 Your H3SH public server can be hidden
Using H3SH, you can avoid the usual stress of scanning and dictionary attacks against your SSH server. Similarly to your secret Google Drive documents, your H3SH server can be hidden behind a secret link and only answer to authentication attempts that made an HTTP request to this specific link, like the following:

    h3sh-server -bind 192.0.2.0:443 -url-path <my-long-secret>

By replacing `<my-long-secret>` by, let's say, the random value `M3MzkxYWMxMjYxMjc5YzJkODZiMTAyMjU`, your H3SH server will only answer to H3SH connection attempts made to the URL `https://192.0.2.0:443/M3MzkxYWMxMjYxMjc5YzJkODZiMTAyMjU` and it will respond a `404 Not Found` to other requests. Attackers and crawlers on the Internet can therefore not detect the presence of your H3SH server. They will only see a simple web server answering 404 status codes to every request.

## 💐 H3SH is already feature-rich
H3SH provides new feature that could not be provided by the SSHv2 protocol.

### Brand new features
- **UDP port forwarding**: you can now access your QUIC, DNS, RTP or any UDP-based server that are only reachable from your H3SH host.
UDP packets are forwarded using QUIC datagrams.
- **X.509 certificates**: you can now use your classical HTTPS certificates to authenticate your H3SH server. This mechanism is more secure than the classical SSHv2 host key mechanism. Certificates can be obtained easily using LetsEncrypt for instance.
- **Hiding** your server behind a secret link.
- **Keyless** secure user authentication using **OpenID Connect**. You can connect to your H3SH server using the SSO of your company or your Google/Github account, and you don't need to copy the public keys of your users anymore.

### Famous OpenSSH features implemented
This H3SH implementation already provides many of the popular features of OpenSSH, so if you are used to OpenSSH, the process of adopting H3SH will be smooth. Here is a list of some OpenSSH features that H3SH also implements:
- Parses `~/.ssh/authorized_keys` on the server
- Parses `~/.ssh/config` on the client and handles the `Hostname`, `User`, `Port` and `IdentityFile` config options (the other options are currently ignored)
- Certificate-based server authentication
- `known_hosts` mechanism when X.509 certificates are not used.
- Automatically using the `ssh-agent` for public key authentication
- SSH agent forwarding to use your local keys on your remote server
- Direct TCP port forwarding (reverse port forwarding will be implemented in the future)

## Installing H3SH
You can either download the last [release binaries](https://github.com/francoismichel/h3sh/releases),
[install it using `go install`](#installing-h3sh-and-h3sh-server-using-go-install) or generate these binaries yourself by compiling the code from source.

> [!TIP]
> H3SH is still experimental and is the fruit of a research work. If you are afraid of deploying publicly a new H3SH server, you can use the
> [secret path](#-your-h3sh-public-server-can-be-hidden) feature of H3SH to hide it behing a secret URL.

### Installing h3sh and h3sh-server using Go install
```bash
go install github.com/francoismichel/h3sh/cmd/...@v0.1.5-rc2
```



### Compiling H3SH from source
You need a recent [Golang](https://go.dev/dl/) version to do this.
Downloading the source code and compiling the binaries can be done with the following steps:

```bash
git clone https://github.com/francoismichel/h3sh    # clone the repo
cd h3sh
go build -o h3sh cmd/h3sh/main.go                        # build the client
CGO_ENABLED=1 go build -o h3sh-server cmd/h3sh-server/main.go   # build the server, requires having gcc installed
```

If you have root/sudo privileges and you want to make h3sh accessible to all you users,
you can then directly copy the binaries to `/usr/bin`:

```bash
cp h3sh /usr/bin/ && cp h3sh-server /usr/bin
```

Otherwise, you can simply add the executables to your `PATH` environment variable by adding
the following line at the end of your `.bashrc` or equivalent:

```bash
export PATH=$PATH:/path/to/the/h3sh/directory
```

### Deploying an H3SH server
Before connecting to your host, you need to deploy an H3SH server on it. There is currently
no H3SH daemon, so right now, you will have to run the `h3sh-server` executable in background
using `screen` or a similar utility.


> [!NOTE]
> As H3SH runs on top of HTTP/3, a server needs an X.509 certificate and its corresponding private key. If you do not want to generate a certificate signed by a real certificate authority, you can generate a self-signed one using the `generate_openssl_selfsigned_certificate.sh` script. This provides you with similar security guarantees to SSHv2's host keys mechanism, with the same security issue: you may be vulnerable to machine-in-the-middle attacks during your first connection to your server. Using real certificates signed by public certificate authorities such as Let's Encrypt avoids this issue.


Here is the usage of the `h3sh-server` executable:

```
Usage of ./h3sh-server:
  -bind string
        the address:port pair to listen to, e.g. 0.0.0.0:443 (default "[::]:443")
  -cert string
        the filename of the server certificate (or fullchain) (default "./cert.pem")
  -enable-password-login
        if set, enable password authentication (disabled by default)
  -generate-selfsigned-cert
        if set, generates a self-self-signed cerificate and key that will be stored
        at the paths indicated by the -cert and -key args (they must not already exist)
  -key string
        the filename of the certificate private key (default "./priv.key")
  -url-path string
        the secret URL path on which the h3sh server listens (default "/h3sh-term")
  -v    verbose mode, if set
```

The following command starts a public H3SH server on port 443 and answers to new
sessions requests querying the `/h3sh` URL path:

    h3sh-server -cert /path/to/cert/or/fullchain -key /path/to/cert/private/key -url-path /h3sh

> [!NOTE]
> Similarly to OpenSSH, the server must be run with root priviledges to log in as other users.

#### Authorized keys and authorized identities
By default, the H3SH server will look for identities in the `~/.ssh/authorized_keys` and `~/.h3sh/authorized_identities` files for each user.
`~/.h3sh/authorized_identities` allows new identities such as OpenID Connect (`oidc`) discussed [below](#openid-connect-authentication-still-experimental).
Popular key types such as `rsa`, `ed25519` and keys in the OpenSSH format can be used.

### Using the H3SH client
Once you have an H3SH server running, you can connect to it using the H3SH client similarly to what
you did with your classical SSHv2 tool.

Here is the usage of the `h3sh` executable:

```
Usage of h3sh:
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

#### Private-key authentication
You can connect to your H3SH server at my-server.example.org listening on `/my-secret-path` using the private key located in `~/.ssh/id_rsa` with the following command:

      h3sh -privkey ~/.ssh/id_rsa username@my-server.example.org/my-secret-path

#### Agent-based private key authentication
The H3SH client works with the OpenSSH agent and uses the classical `SSH_AUTH_SOCK` environment variable to
communicate with this agent. Similarly to OpenSSH, H3SH will list the keys provided by the SSH agent
and connect using the first key listen by the agent by default.
If you want to specify a specific key to use with the agent, you can either specify the private key
directly with the `-privkey` argument like above, or specify the corresponding public key using the
`-pubkey-for-agent` argument. This allows you to authenticate in situations where only the agent has
a direct access to the private key but you only have access to the public key.

#### Password-based authentication
While discouraged, you can connect to your server using passwords (if explicitly enabled on the `h3sh-server`)
with the following command:

      h3sh -use-password username@my-server.example.org/my-secret-path

#### Config-based session establishment
`h3sh` parses your OpenSSH config. Currently, it only handles the `Hostname`; `User`, `Port` and `IdentityFile` options.
Let's say you have the following lines in your OpenSSH config located in `~/.ssh/config` :
```
Host my-server
  HostName 192.0.2.0
  User username
  IdentityFile ~/.ssh/id_rsa
```

Similarly to what OpenSSH does, the following `h3sh` command will connect you to the H3SH server running on 192.0.2.0 on UDP port 443 using public key authentication with the private key located in `.ssh/id_rsa` :

      h3sh my-server/my-secret-path

If you do not want a config-based utilization of H3SH, you can read the sections below to see how to use the CLI parameters of `h3sh`.

#### OpenID Connect authentication (still experimental)
This feature allows you to connect using an external identity provider such as the one
of your company or any other provider that implements the OpenID Connect standard, such as Google Identity,
Github or Microsoft Entra. The authentication flow is illustrated in the GIF below.

<div align="center">
<img src="resources/figures/h3sh_oidc.gif" width=75%>

*Secure connection without private key using a Google account.*
</div>

The way it connects to your identity provider is configured in a file named `~/.h3sh/oidc_config.json`.
Below is an example `config.json` file for use with a Google account. This configuration file is an array
and can contain several identity providers configurations.
```json
[
    {
        "issuer_url": "https://accounts.google.com",
        "client_id": "<your_client_id>",
        "client_secret": "<your_client_secret>"
    }
]
```
This might change in the future, but currently, to make this feature work with your Google account, you will need to setup a new experimental application in your Google Cloud console and add your email as authorized users.
This will provide you with a `client_id` and a `client_secret` that you can then set in your `~/.h3sh/oidc_config.json`. On the server side, you just have to add the following line in your `~/.h3sh/authorized_identities`:

```
oidc <client_id> https://accounts.google.com <email>
```
We currently consider removing the need of setting the client_id in the `authorized_identities` file in the future.
