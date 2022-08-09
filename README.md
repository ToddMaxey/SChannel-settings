# Secure Cipher Suites allowed, ordering for TLS 1.2, 1.3 with general Schannel security guidance for Windows 1x, Server 2022

The following guidance is to allow only the strongest cipher suites for TLS 1.2 and TLS 1.3 that also are allowed by the .Net setting of SCH\_USE\_STRONG\_CRYPTO and to eliminate other cryptographic elements that are weak on insecure.

You can check to determine the security status of a cipher suite at [https://ciphersuite.info/](https://ciphersuite.info/)

Note: The registry settings at "HKEY\_LOCAL\_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL" are unsupported except for the Protocols path, and should be controlled by the deliberate selection of cipher suites using [PowerShell TLS cmdlets](https://docs.microsoft.com/en-us/powershell/module/tls/?view=windowsserver2022-ps) or via [Group Policy](https://docs.microsoft.com/en-us/windows-server/security/tls/manage-tls) as the preferred method of configuration.

**First business:**

**Security notes regarding insecure cryptographic elements:**

**It is a REALLY good idea to disabled all algorithms and protocols that are insecure**

**Review cryptographic suite elements and remove known compromised elements.**

HKEY\_LOCAL\_MACHINE\SYSTEM\CurrentControlSet\Control\Cryptography\Configuration\Local\SSL\00010003.Functions

Example data:

RSAE-PSS/SHA256

RSAE-PSS/SHA384

RSAE-PSS/SHA512

RSA/SHA256

RSA/SHA384

RSA/SHA1

ECDSA/SHA256

ECDSA/SHA384

ECDSA/SHA1

DSA/SHA1

RSA/SHA512

ECDSA/SHA512

(the red highlighted line items should be deleted as they are compromised or contain weak cryptographic elements)

**How to** [**Restrict cryptographic algorithms and protocols - Windows Server | Microsoft Docs**](https://docs.microsoft.com/en-us/troubleshoot/windows-server/windows-security/restrict-cryptographic-algorithms-protocols-schannel)

**Current (8/2022) list of weak or insecure cryptographic elements**

**The Secure Hash Algorithm 1 (SHA1 or SHA)** has been shown as insecure as of 2017. Review [**shattered.io**](https://shattered.io/) for details.

**Data Encryption Standard (DES)** is weak due to its short key-lengths of 40 or 65-Bit. In 2005 the National Institute of Standards and Technology has withdrawn DES as a standard.

**Triple-DES** is still utilized as a secure symmetric-key encryption, but a number of standardizations bodies and projects have deprecate Triple-DES even though it has not broken, in the past, it has been shown to suffer from several vulnerabilities.

**Cipher Block Chaining (CBC)** was demonstrated in 2013 by researchers utilizing a timing attack against several TLS implementations using the encryption algorithm. Also, CBC mode is vulnerable to plain-text attacks in TLS 1.0, SSL 3.0 and lower. A fix has been introduced with TLS 1.2 in the form of the GCM mode which is not vulnerable to the BEAST attack. GCM should be preferred over CBC. Review  [**isg.rhul.ac.uk**](http://www.isg.rhul.ac.uk/tls/Lucky13.html) for more details.

**Anonymous (ANON)** key exchange is vulnerable to Man in the Middle attacks

**NULL Authentication** uses no authentication and does not provide integrity.

**NULL Encryption** uses no encryption at all which does not provide any confidentiality.

**Rivest Cipher 4 (RC4)** has officially been prohibited by the IETF for use in TLS in RFC 7465 and is considered insecure. [Microsoft security advisory: Update for disabling RC4](https://support.microsoft.com/en-us/topic/microsoft-security-advisory-update-for-disabling-rc4-479fd6f0-c7b5-0671-975b-c45c3f2c0540)

**Message Digest 5 (MD5)** has multiple vulnerabilities and is considered insecure.

**ShangMi 3 (SM3)** hashing algorithm is a Chinese algorithm, which will be or is already mandatory for TLS encrypted connections in China. The security of this algorithm is not proven, and its use is not recommended by the IETF. For further details review [https://tools.ietf.org/html/rfc8998](https://tools.ietf.org/html/rfc8998)

**ShangMi 4 (SM4)** encryption algorithm is a Chinese algorithm, which will be or is already mandatory for TLS encrypted connections in China. The security of this algorithm is not proven, and its use is not recommended by the IETF. For further details review [https://tools.ietf.org/html/rfc8998](https://tools.ietf.org/html/rfc8998)

**Diffie-Hellman (DH)** is a Non-ephemeral Key Exchange and does not support Perfect Forward Secrecy (PFS) which is recommended, so an attacker is unable to decrypt the complete communication stream.

**Elliptic Curve Diffie-Hellman (ECDH)** is a Non-ephemeral Key Exchange and does not support Perfect Forward Secrecy (PFS) which is recommended, so an attacker is unable to decrypt the complete communication stream.

**Kerberos 5 (KRB5)** is a Non-ephemeral Key Exchange and does not support Perfect Forward Secrecy (PFS) which is recommended, so an attacker is unable to decrypt the complete communication stream.

**Rivest Cipher 2 (RC2)** A related-key attack discovered in 1997 renders it insecure. For further details review [https://www.schneier.com/wp-content/uploads/2016/02/paper-relatedkey.pdf](https://www.schneier.com/wp-content/uploads/2016/02/paper-relatedkey.pdf)

Notes: Windows TLS stack never supported non-ephemeral (EC)DH. The only non-PFS cipher suites supported in schannel are TLS\_RSA

**SSL/TLS insecure protocols which should be disabled for client and server on every machine:**

Multi-Protocol Unified Hello

SSL 2.0

SSL 3.0

TLS 1.0

TLS 1.1

Schannel registry settings - [Transport Layer Security (TLS) registry settings | Microsoft Docs](https://docs.microsoft.com/en-us/windows-server/security/tls/tls-registry-settings) - The registry values that are being utilized and supported.

[DTLS info](https://en.wikipedia.org/wiki/Datagram_Transport_Layer_Security)

**.Net security considerations**

**SchUseStrongCrypto**

The HKEY\_LOCAL\_MACHINE\SOFTWARE\ [Wow6432Node\]Microsoft\.NETFramework\\<VERSION\>: SchUseStrongCrypto registry key has a value of type DWORD. A value of 1 causes your app to use strong cryptography. The strong cryptography uses more secure network protocols (TLS 1.2, TLS 1.1, and TLS 1.0) and blocks protocols that are not secure. A value of 0 disables strong cryptography. For more information, see [The SCH\_USE\_STRONG\_CRYPTO flag](https://docs.microsoft.com/en-us/dotnet/framework/network-programming/tls#the-sch_use_strong_crypto-flag). This registry setting affects only client (outgoing) connections in your application.

If your app targets .NET Framework 4.6 or later versions, this key defaults to a value of 1. That's a secure default that we recommend. If your app targets .NET Framework 4.5.2 or earlier versions, the key defaults to 0. In that case, you should explicitly set its value to 1.

This key should only have a value of 0 if you need to connect to legacy services that don't support strong cryptography and can't be upgraded.

**SystemDefaultTlsVersions**

The HKEY\_LOCAL\_MACHINE\SOFTWARE\ [Wow6432Node\]Microsoft\.NETFramework\\<VERSION\>: SystemDefaultTlsVersions registry key has a value of type DWORD. A value of 1 causes your app to allow the operating system to choose the protocol. A value of 0 causes your app to use protocols picked by the .NET Framework.

\<VERSION\> must be v4.0.30319 (for .NET Framework 4 and above) or v2.0.50727 (for .NET Framework 3.5).

If your app targets .NET Framework 4.7 or later versions, this key defaults to a value of 1. That's a secure default that we recommend. If your app targets .NET Framework 4.6.1 or earlier versions, the key defaults to 0. In that case, you should explicitly set its value to 1.

For more info, see [Cumulative Update for Windows 10 Version 1511 and Windows Server 2016 Technical Preview 4: May 10, 2016](https://support.microsoft.com/help/3156421/cumulative-update-for-windows-10-version-1511-and-windows-server-2016).

For more information with .NET Framework 3.5.1, see [Support for TLS System Default Versions included in .NET Framework 3.5.1 on Windows 7 SP1 and Server 2008 R2 SP1](https://support.microsoft.com/help/3154518/support-for-tls-system-default-versions-included-in-the--net-framework).

The following _.REG_ file sets the registry keys and their variants to their most safe values:

Windows Registry Editor Version 5.00

[HKEY\_LOCAL\_MACHINE\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v2.0.50727]
 "SystemDefaultTlsVersions"=dword:00000001
 "SchUseStrongCrypto"=dword:00000001

[HKEY\_LOCAL\_MACHINE\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319]
 "SystemDefaultTlsVersions"=dword:00000001
 "SchUseStrongCrypto"=dword:00000001

[HKEY\_LOCAL\_MACHINE\SOFTWARE\Microsoft\.NETFramework\v2.0.50727]
 "SystemDefaultTlsVersions"=dword:00000001
 "SchUseStrongCrypto"=dword:00000001

[HKEY\_LOCAL\_MACHINE\SOFTWARE\Microsoft\.NETFramework\v4.0.30319]
 "SystemDefaultTlsVersions"=dword:00000001
 "SchUseStrongCrypto"=dword:00000001

Configuring Schannel protocols in the Windows Registry

You can use the registry for fine-grained control over the protocols that your client and/or server app negotiates. Your app's networking goes through Schannel (which is another name for [Secure Channel](https://docs.microsoft.com/en-us/windows/desktop/SecAuthN/secure-channel). By configuring Schannel, you can configure your app's behavior.

Start with the HKEY\_LOCAL\_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols registry key. Under that key you can create any subkeys in the set SSL 2.0, SSL 3.0, TLS 1.0, TLS 1.1, and TLS 1.2. Under each of those subkeys, you can create subkeys Client and/or Server. Under Client and Server, you can create DWORD values DisabledByDefault (0 or 1) and Enabled (0 or 1).

The SCH\_USE\_STRONG\_CRYPTO flag

When it's enabled (by default, by [an AppContext switch](https://docs.microsoft.com/en-us/dotnet/framework/network-programming/tls#switchsystemnetdontenableschusestrongcrypto), or [by the Windows Registry](https://docs.microsoft.com/en-us/dotnet/framework/network-programming/tls#schusestrongcrypto)), the .NET Framework uses the SCH\_USE\_STRONG\_CRYPTO flag when your app initiates a TLS connection to a server. .NET Framework passes the flag to Schannel to instruct it to disable known weak cryptographic algorithms, cipher suites, and TLS/SSL protocol versions that may be otherwise enabled for better interoperability. For more information, see:

- [Secure Channel](https://docs.microsoft.com/en-us/windows/desktop/SecAuthN/secure-channel)
- [SCHANNEL\_CRED structure](https://docs.microsoft.com/en-us/windows/win32/api/schannel/ns-schannel-schannel_cred)

The SCH\_USE\_STRONG\_CRYPTO flag is also passed to Schannel for client (outgoing) connections when you explicitly use the Tls (TLS 1.0), Tls11, or Tls12 enumerated values of [SecurityProtocolType](https://docs.microsoft.com/en-us/dotnet/api/system.net.securityprotocoltype) or [SslProtocols](https://docs.microsoft.com/en-us/dotnet/api/system.security.authentication.sslprotocols). The SCH\_USE\_STRONG\_CRYPTO flag is used only for connections where your application acts the role of the client. You can disable weak protocols and algorithms when your applications acts the role of the server by configuring the machine-wide Schannel registry settings.



**Performance notes:**

**RSA Authentication** has been reported that servers using the algorithm with \>=3072-bit keys could experience large performance issues leading to connection timeouts and even service unavailability if a large numbed clients open simultaneous connections.

**Review the current cipher suites being utilized on the machine.**

Get-TlsCipherSuite | Format-Table Name

**Disabled insecure cipher suites - Note: The cipher suites being disabled in this list all have insecure or weak features.**

| **Disable-TlsCipherSuite -Name "TLS\_DHE\_DSS\_WITH\_AES\_128\_CBC\_SHA"** |
| --- |
| **Disable-TlsCipherSuite -Name "TLS\_DHE\_DSS\_EXPORT1024\_WITH\_DES\_CBC\_SHA"** |
| **Disable-TlsCipherSuite -Name "TLS\_DHE\_DSS\_WITH\_3DES\_EDE\_CBC\_SHA"** |
| **Disable-TlsCipherSuite -Name "TLS\_DHE\_DSS\_WITH\_AES\_128\_GCM\_SHA256"** |
| **Disable-TlsCipherSuite -Name "TLS\_DHE\_DSS\_WITH\_AES\_256\_CBC\_SHA"** |
| **Disable-TlsCipherSuite -Name "TLS\_DHE\_DSS\_WITH\_AES\_256\_GCM\_SHA384"** |
| **Disable-TlsCipherSuite -Name "TLS\_DHE\_DSS\_WITH\_ARIA\_128\_GCM\_SHA256"** |
| **Disable-TlsCipherSuite -Name "TLS\_DHE\_DSS\_WITH\_ARIA\_256\_GCM\_SHA384"** |
| **Disable-TlsCipherSuite -Name "TLS\_DHE\_DSS\_WITH\_CAMELLIA\_128\_GCM\_SHA256"** |
| **Disable-TlsCipherSuite -Name "TLS\_DHE\_DSS\_WITH\_CAMELLIA\_256\_GCM\_SHA384"** |
| **Disable-TlsCipherSuite -Name "TLS\_DHE\_DSS\_WITH\_DES\_CBC\_SHA"** |
| **Disable-TlsCipherSuite -Name "TLS\_DHE\_PSK\_WITH\_AES\_128\_GCM\_SHA256"** |
| **Disable-TlsCipherSuite -Name "TLS\_DHE\_PSK\_WITH\_AES\_256\_GCM\_SHA384"** |
| **Disable-TlsCipherSuite -Name "TLS\_DHE\_PSK\_WITH\_ARIA\_128\_GCM\_SHA256"** |
| **Disable-TlsCipherSuite -Name "TLS\_DHE\_PSK\_WITH\_ARIA\_256\_GCM\_SHA384"** |
| **Disable-TlsCipherSuite -Name "TLS\_DHE\_PSK\_WITH\_CAMELLIA\_128\_GCM\_SHA256"** |
| **Disable-TlsCipherSuite -Name "TLS\_DHE\_PSK\_WITH\_CAMELLIA\_256\_GCM\_SHA384"** |
| **Disable-TlsCipherSuite -Name "TLS\_DHE\_PSK\_WITH\_CHACHA20\_POLY1305\_SHA256"** |
| **Disable-TlsCipherSuite -Name "TLS\_DHE\_RSA\_WITH\_AES\_128\_CBC\_SHA"** |
| **Disable-TlsCipherSuite -Name "TLS\_DHE\_RSA\_WITH\_AES\_256\_CBC\_SHA"** |
| **Disable-TlsCipherSuite -Name "TLS\_ECDHE\_ECDSA\_WITH\_AES\_128\_CBC\_SHA"** |
| **Disable-TlsCipherSuite -Name "TLS\_ECDHE\_ECDSA\_WITH\_AES\_256\_CBC\_SHA"** |
| **Disable-TlsCipherSuite -Name "TLS\_ECDHE\_ECDSA\_WITH\_ARIA\_128\_GCM\_SHA256"** |
| **Disable-TlsCipherSuite -Name "TLS\_ECDHE\_ECDSA\_WITH\_ARIA\_256\_GCM\_SHA384"** |
| **Disable-TlsCipherSuite -Name "TLS\_ECDHE\_ECDSA\_WITH\_CAMELLIA\_128\_GCM\_SHA256"** |
| **Disable-TlsCipherSuite -Name "TLS\_ECDHE\_ECDSA\_WITH\_CAMELLIA\_256\_GCM\_SHA384"** |
| **Disable-TlsCipherSuite -Name "TLS\_ECDHE\_ECDSA\_WITH\_CHACHA20\_POLY1305\_SHA256"** |
| **Disable-TlsCipherSuite -Name "TLS\_ECDHE\_PSK\_WITH\_AES\_128\_GCM\_SHA256"** |
| **Disable-TlsCipherSuite -Name "TLS\_ECDHE\_PSK\_WITH\_AES\_256\_GCM\_SHA384"** |
| **Disable-TlsCipherSuite -Name "TLS\_ECDHE\_PSK\_WITH\_CHACHA20\_POLY1305\_SHA256"** |
| **Disable-TlsCipherSuite -Name "TLS\_ECDHE\_RSA\_WITH\_AES\_128\_CBC\_SHA"** |
| **Disable-TlsCipherSuite -Name "TLS\_ECDHE\_RSA\_WITH\_AES\_256\_CBC\_SHA"** |
| **Disable-TlsCipherSuite -Name "TLS\_RSA\_EXPORT\_WITH\_RC4\_40\_MD5"** |
| **Disable-TlsCipherSuite -Name "TLS\_RSA\_EXPORT1024\_WITH\_DES\_CBC\_SHA"** |
| **Disable-TlsCipherSuite -Name "TLS\_RSA\_EXPORT1024\_WITH\_RC4\_56\_SHA"** |
| **Disable-TlsCipherSuite -Name "TLS\_RSA\_WITH\_3DES\_EDE\_CBC\_SHA"** |
| **Disable-TlsCipherSuite -Name "TLS\_RSA\_WITH\_AES\_128\_CBC\_SHA"** |
| **Disable-TlsCipherSuite -Name "TLS\_RSA\_WITH\_AES\_256\_CBC\_SHA"** |
| **Disable-TlsCipherSuite -Name "TLS\_RSA\_WITH\_DES\_CBC\_SHA"** |
| **Disable-TlsCipherSuite -Name "TLS\_RSA\_WITH\_NULL\_MD5"** |
| **Disable-TlsCipherSuite -Name "TLS\_RSA\_WITH\_NULL\_SHA"** |
| **Disable-TlsCipherSuite -Name "TLS\_RSA\_WITH\_RC4\_128\_MD5"** |
| **Disable-TlsCipherSuite -Name "TLS\_RSA\_WITH\_RC4\_128\_SHA"** |
| **Disable-TlsCipherSuite -Name "TLS\_SHA256\_SHA256"** |
| **Disable-TlsCipherSuite -Name "TLS\_SHA384\_SHA384"** |
| **Disable-TlsCipherSuite -Name "TLS\_RSA\_WITH\_AES\_256\_GCM\_SHA384"** |
| **Disable-TlsCipherSuite -Name "TLS\_RSA\_WITH\_AES\_128\_GCM\_SHA256"** |



**Enabling or disabling additional cipher suites**

You can disable certain specific ciphers by removing them from HKEY\_LOCAL\_MACHINE\SYSTEM\CurrentControlSet\Control\Cryptography\Configuration\Local\SSL\00010002 in the registry.

Note: The "SSL\00010002" registry key is controlled by a Group Policy that can be set locally or in a Group Policy Object. This designates the cipher suites that are enabled and the order which they are presented.

To configure the SSL Cipher Suite Order group policy setting

1. At a command prompt, enter gpedit.msc

  1. The Group Policy Object Editor appears.
1. Expand Computer Configuration, Administrative Templates, Network, and then click SSL Configuration Settings.
2. Under SSL Configuration Settings, click the SSL Cipher Suite Order setting.
3. In the SSL Cipher Suite Order pane, scroll to the bottom of the pane.
4. Follow the instructions labeled How to modify this setting.

  1. String for GPO for above cipher suite order

    1. TLS\_CHACHA20\_POLY1305\_SHA256,TLS\_AES\_128\_GCM\_SHA256,TLS\_AES\_256\_GCM\_SHA384,TLS\_ECDHE\_ECDSA\_WITH\_AES\_256\_GCM\_SHA384,TLS\_ECDHE\_ECDSA\_WITH\_AES\_128\_GCM\_SHA256,TLS\_PSK\_WITH\_AES\_256\_GCM\_SHA384,TLS\_PSK\_WITH\_AES\_128\_GCM\_SHA256,TLS\_ECDHE\_RSA\_WITH\_AES\_256\_GCM\_SHA384,TLS\_ECDHE\_RSA\_WITH\_AES\_128\_GCM\_SHA256,TLS\_DHE\_RSA\_WITH\_AES\_128\_GCM\_SHA256

1. **It is necessary to restart the computer after modifying this setting for the changes to take effect.**



![](RackMultipart20220809-1-vaxg8b_html_647fef6d23924e47.png)

Screenshot of the Registry Editor showing the Edit Multi-String dialog box for the 00010002 folder.

To enable a cipher suite, add its string value to the Functions multi-string value key or preferably to the policy "SSL Configuration Settings". As an example, if we want to enable TLS\_ECDHE\_RSA\_WITH\_AES\_256\_CBC\_SHA384\_P521 then we would add it to the string.

For a full list of supported Cipher suites see [Cipher Suites in TLS/SSL (Schannel SSP)](https://docs.microsoft.com/en-us/windows/win32/secauthn/cipher-suites-in-schannel). This document provides a table of suites that are enabled by default and those that are supported but not enabled by default. To prioritize the cipher suites, see [Prioritizing Schannel Cipher Suites](https://docs.microsoft.com/en-us/windows/win32/secauthn/prioritizing-schannel-cipher-suites).

The following is a list of cipher suites that are Windows supports for TLS 1.2 and TLS 1.3, are allowed by SCH\_USE\_STRONG\_CRYPTO and support Perfect Forward Secrecy (PFS) and that have no known weakness or insecurity in any element as of 7/2022.

| **Cipher suite string** | **Allowed by SCH\_USE\_STRONG\_CRYPTO** | **TLS/SSL Protocol versions** |
| --- | --- | --- |
| **TLS\_CHACHA20\_POLY1305\_SHA256** | Yes | TLS 1.3 |
| **TLS\_AES\_128\_GCM\_SHA256** | Yes | TLS 1.3 |
| **TLS\_AES\_256\_GCM\_SHA384** | Yes | TLS 1.3 |
| **TLS\_ECDHE\_ECDSA\_WITH\_AES\_256\_GCM\_SHA384** | Yes | TLS 1.2 |
| **TLS\_ECDHE\_ECDSA\_WITH\_AES\_128\_GCM\_SHA256** | Yes | TLS 1.2 |
| **TLS\_PSK\_WITH\_AES\_256\_GCM\_SHA384** | Yes | TLS 1.2 |
| **TLS\_PSK\_WITH\_AES\_128\_GCM\_SHA256** | Yes | TLS 1.2 |
| **TLS\_ECDHE\_RSA\_WITH\_AES\_256\_GCM\_SHA384** | Yes | TLS 1.2 |
| **TLS\_ECDHE\_RSA\_WITH\_AES\_128\_GCM\_SHA256** | Yes | TLS 1.2 |
| **TLS\_DHE\_RSA\_WITH\_AES\_128\_GCM\_SHA256** | Yes | TLS 1.2 |
