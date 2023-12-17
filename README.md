# `bwv` Bitwarden HTTP api

`bwv` is a small helper application for serving Bitwarden secrets over HTTP(S).

> Note.
> Much of the bitwarden API and cryptography functionality is drawn from the
> `bitw` application (https://github.com/mvdan/bitw) however there is no
> association between the two applications and any issues found with this repo
> should be reported here.
>
> Due to the integrations with KWallet, Libsecret and SystemD, this application
> only works on the Linux platform today.
>
> If someone knows how to integrate similar functionality on other platforms,
> I would welcome pull requests.

---
**Disclaimer**

I am not a cryptographer, nor do I make any such claim to being one; neither am
I affiliated with Bitwarden in any way.

This code is a personal project to wrap the Bitwarden API and present secrets
for use inside my environment but I am not responsible for the cryptographic
functions used to encrypt secrets other than the wrappers you find in this
library and application. If you have questions or concerns regarding how
secrets are encrypted, please discuss these with with Bitwarden directly.

Whilst every effort is taken to ensure this application handles secrets in a
secure manner during its normal operation, including the use of guarded memory,
cryptographic shredding of passwords and hashes and ensuring decrypted secrets
are kept in memory for the minimal amount of time, certain functionality
provided as part of this application offers the opportinity for secrets to be
leaked and should thus be used with caution.

This is no different than any other API or wallet service and the authentication
for the API can (and should) be tied to a wallet service ensuring access to the
server is not available for users outside of your own current session.
---

## Configuration
To configure `bwv` to access your Bitwarden account details, you may do this in
a number of ways:

- Environment
- kwallet
- libsecrets

In all instances, `BW_CLIENTID` and `BW_CLIENTSECRET` are optional but
recommended to prevent continuous prompting for 2fa

```
BW_CLIENTID
BW_CLIENTSECRET
BW_PASSWORD
BW_EMAIL
```

### Environment variables
Create the environment variables containing the credentials.

## kwallet
Store the above secrets in kwallet at `/Passwords/bwvault`

## libsecrets
Use the libsecrets manager of your choice and store the above secrets as
attributes at the same `/Passwords/bwvault`.

## Building
Clone this repo then run `go build .`

## Commands:

> Note:
> The commands listed here, including credential access, are only available to localhost.
> If you need to access credentials over the network, see the API documention below.

- `serve` Run bwv server in foreground.
- `service`
  - `install` Install the userspace systemd service
  - `start` Start the userspace systemd service
  - `stop` stop the userspace systemd service
  - `status` Get the status of the service (usually one of "running" or "dead")
  - `remove` Stop the userspace systemd service and remove it entirely.
- `key`
  - `genkey <ip address|cidr range>` Create a 32 character random string to use
     as an API key, bound to the provided address or cidr range
  - `revoke <key>` Revokes the given key. Future iterations will allow for an ip or range to be provided if the key is lost.
- `path/to/secret[?[field|property]=value` Get the secret at a given path,
  optionally followed by specific properties to read

## Usage

Run the server

```plaintext
$ bwv serve
2022/04/03 07:20:33 Login complete
2022/04/03 07:20:36 Master password configured
2022/04/03 07:20:36 Loading config file /home/mproffitt/.config/bwv/server.yaml
2022/04/03 07:20:36 Sync complete
2022/04/03 07:20:36 Listening for secure connections on :6277 (whitelist [127.0.0.0/24])
```

Retrieve a credential

```plaintext
$ bwv example/test
[
  {
    "fields": {
      "unseal-1": "abcdef",
      "unseal-2": "123456"
    },
    "folder_id": "804e76c5-c7fe-4a4b-94ef-ae6700d79146",
    "id": "2d29507c-72ef-493b-a09f-ae6700d83380",
    "name": "test",
    "password": "GGAPP$KoQ499hDCBHqvCxURzzS$3bp*A",
    "revision_date": "2022-03-29T13:07:09.8566667Z",
    "type": 1,
    "username": "invalid@example.com"
  }
]
```

### Wildcards

The following wildcard patterns are currently supported

- `*`, `./*` both of these return all credentials which do not have a folder
- `*/*` return all credentials in all folders
- `*/name` return all credentials with name `name` in any folder

A future version may include more advanced search patterns.

### Filtering

When only a single credential is being returned, this can be filtered to only
return certain properties and/or fields by adding http query options onto the
end of the path.

> Note:
> Do not use filters with wildcards as this may give unexpected results.

If only a single property or field is being returned, this will always be
identified as `value` in the resulting json object.

```
$ bwv example/test?property=password
{
  "value": "GGAPP$KoQ499hDCBHqvCxURzzS$3bp*A"
}
```

Multiple properties/fields can be requested with the following examples being
equivelant

```
$ bwv example/test -p password -p username -f unseal-1 -f unseal-2
{
  "password": "GGAPP$KoQ499hDCBHqvCxURzzS$3bp*A",
  "unseal-1": "abcdef",
  "unseal-2": "123456",
  "username": "invalid@example.com"
}
```

```
$ bwv 'example/test?properties=username,password&fields=unseal-1,unseal-2'
{
  "password": "GGAPP$KoQ499hDCBHqvCxURzzS$3bp*A",
  "unseal-1": "abcdef",
  "unseal-2": "123456",
  "username": "invalid@example.com"
}
```

### Whitelisting

When you first try and run `bwv` it will setup the server.yaml file and add 127.0.0.0/24 as the only whitelisted ip range.

To whitelist other IPs or ranges, either edit the configuration file or use the `whitelist` command.

```
$ bwv whitelist 192.168.1.8/30
```

HTTP only exists for running on a local network, behind a firewall where it cannot and should never be accessed from the
outside world. It is serving your passwords and these should never be transmitted in plaintext, even when you trust the
requesting device.

I do not recommend using the HTTP only version, even for local connections. Setting up a local CA and certificates is
simple and cheap, and if you need to serve externally, letsencrypt is your friend.

### API tokens

When connecting to the `bwv` server from any address other than `localhost`, an
API token is required.

Localhost uses either your `BW_CLIENTSECRET` or `BW_PASSWORD` to achieve this
with the preference being `BW_CLIENTSECRET`.

An api token is a random 32 character string which is stored encrypted in the
server configuration. The encryption uses a `pbkdf2` key derived from your
master password. You are given the plaintext string which should be submitted as
a `Bearer` token when accessing the api. See below.

To generate an API token, use the genkey command.

```
$ bwv genkey 192.168.1.5
2022/04/03 07:55:26 Login complete
2022/04/03 07:55:29 Master password configured
2022/04/03 07:55:29 Loading config file /home/mproffitt/.config/bwv/server.yaml

========================================
token = TQ5d0IEyOEPAtgZmV76oOc0WqpU5VdDO
========================================
```

Tokens can be revoked either by specifying the token, or the address the token
is associated with however if the address is part of a range, the token must be
used.

```
$ bwv revoke 192.168.1.5
2022/04/03 07:58:21 Login complete
2022/04/03 07:58:23 Master password configured
2022/04/03 07:58:23 Loading config file /home/mproffitt/.config/bwv/server.yaml
```

### Advanced configuration
For more advanced configuration, create or edit the file at
`${HOME}/.config/bwv/server.yaml` in which the following properties are allowed:

- `whitelist` A list of IP addresses allowed to access the service
- `cert` An SSL certificate to secure your credentials in transit
- `key` The SSL certificates key
- `port` The port to listen on. This must be above 1024 if running in userspace.
  If port is 0, defaults to 6277
- `apikeys` You generally do not want to touch this map. Use `./bwv genkey`
  and `./bwv revoke` to manage this.

## API
The API for this application is simple.

- `genkey` [INTERNAL]
- `revokekey` [INTERNAL]
- `/reload` [INTERNAL] Tells the server to reload its config. Normally you do
  not need to access this endpoint.
- `/path/to/credential` get the full contents at `path/to/credential`.
- `/path/?property=username[,password]` A top level attribute from the
  credential such as username or password.
- `/path/?field=my-custom-field[,another-field]` Fields are custom attributes
  set on the credential.

All API calls must be made with an API token passed along with the request as a
Bearer token.

```
$ curl -s -H "Authorization: Bearer TQ5d0IEyOEPAtgZmV76oOc0WqpU5VdDO" \
    https://example.com:6277/example/test
```

Failure to provide a token, using anything other than `Bearer`, or using a token
not assigned to the address or range you are accessing the API from, will result
in a `403 Permission Denied` response.
