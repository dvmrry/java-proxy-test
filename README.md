# ProxyTest

Single-file Java proxy diagnostics tool. No build tools, no dependencies — just `javac` and `java` (11+).

## Quick Start

```bash
javac ProxyTest.java
java ProxyTest
```

Edit `proxytest.properties` to configure your proxy, targets, and trust store. Changes take effect on next run — no recompilation needed.

## What It Does

Runs 5 diagnostic phases against your proxy:

| Phase | What | Why |
|-------|------|-----|
| 1. DNS | Resolves proxy hostname | Catches DNS misconfig |
| 2. TCP | Raw socket connect to proxy | Catches firewall/routing issues |
| 3. TLS | SSL handshake to proxy | Catches cert/protocol mismatches |
| 4. CONNECT | Raw `HTTP CONNECT` tunnel request | Proves proxy accepts tunneling |
| 5. HTTP | Full GET/PUT/POST through proxy | End-to-end validation |

Each phase isolates a layer, so when something fails you know exactly where.

## Configuration

Copy and edit `proxytest.properties`:

```properties
proxy.mode=config
proxy.host=proxy.example.com
proxy.port=9443

# Custom trust store (leave blank for Java default)
truststore.path=/etc/pki/java/cacerts
truststore.password=changeit

# Hosts that bypass proxy (pipe-delimited)
nonProxyHosts=*.example.com|localhost

# What to test
targets=builtin
http.method=GET

# Skip phases you don't need: dns, tcp, tls, connect, http
skip=
```

Set `targets=builtin` to hit 9 public endpoints (httpbin, google, cloudflare, etc.) or provide your own comma-separated URLs.

A sample Confluence/Tomcat config is included in `proxytest-confluence.properties`.

## Usage

```bash
# Default config in current directory
java ProxyTest

# Custom config file
java ProxyTest /path/to/myconfig.properties

# With SSL debug output (verbose TLS handshake logging)
java -Djavax.net.debug=ssl,handshake ProxyTest

# If the environment already sets JVM proxy props (e.g. CATALINA_OPTS),
# set proxy.mode=system to pick those up automatically

# Show all options
java ProxyTest --help
```

## TLS / Custom Trust Store

If your proxy intercepts HTTPS (e.g. Zscaler, corporate SSL inspection), Java won't trust it by default. You need to import the intercepting CA into a local keystore:

```bash
# Export certs from macOS keychain (search for your org's CA name)
security find-certificate -a -c "YourOrg" -p /Library/Keychains/System.keychain > /tmp/ca-bundle.pem

# Or on Linux, get the proxy's cert chain directly
openssl s_client -connect proxy.example.com:9443 -showcerts </dev/null 2>/dev/null | openssl x509 -outform PEM > /tmp/ca-bundle.pem

# Copy Java's default trust store locally
cp $JAVA_HOME/lib/security/cacerts ./cacerts

# Import all certs from the bundle
./import-certs.sh /tmp/ca-bundle.pem ./cacerts
```

Then set `truststore.path=./cacerts` in your properties file.

## Files

- `ProxyTest.java` — the tool (single file, no dependencies)
- `proxytest.properties` — default config (generic placeholders)
- `proxytest-confluence.properties` — sample config for Confluence/Tomcat environments
- `import-certs.sh` — helper to import PEM cert bundles into a Java keystore
