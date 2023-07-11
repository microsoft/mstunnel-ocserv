Using Cisco IP-Phones with ocserv
=================================

The 'Enterprise' firmware on the 7800, 8800, 8900 and 9900 series
Cisco IP-Phones can use ocserv as a VPN gateway.

An 'Enterprise' specific URL path of `/svc` is required when
configuring the phone. In the phone's `SEPMAC.cnf.xml` that looks
like:
```
  <vpnGroup>
     ...
     <addresses>
       <url>https://host.name.for.ocserv/svc</url>
     </addresses>
  </vpnGroup>
```

Both username+password and certificate-based authentication
are supported.

Ocserv configuration
====================

In addition to requiring an 'Enterprise' specific path, ocserv must
also be configured to work-around limitations in the behavior of the
phone's VPN client.

To enable that mode use:
```
cisco-svc-client-compat = true
```

**Note:** If the ciphers do not match the phone will log the error
`old session cipher not returned` in the console log. Older phone
VPN clients may negotiate an unsupported TLS+DTLS cipher so you will
need to force either AES256-CBC or AES128-CBC, eg:

```
tls-priorities = "NONE:%SERVER_PRECEDENCE:%COMPAT:+VERS-TLS-ALL:+SIGN-ALL:+COMP-ALL:+RSA:+SHA1:+AES-256-CBC"
```

**Note:** While you may specify any port to use for HTTPS, the phone
will only use port `443` for DTLS.

Additional information
======================

Refer to the following documentation on [usecallmanager.nz](https://usecallmanager.nz)
for additional information about how to configure the phone's VPN.

* [SEPMAC.cnf.xml](https://usecallmanager.nz/sepmac-cnf-xml.html):
  The main configuration file for the phone.
* [VPN Group](https://usecallmanager.nz/vpn-group.html): VPN
  specific configuration.
