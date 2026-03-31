import java.io.FileInputStream;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.ProxySelector;
import java.net.Socket;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.time.Duration;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.stream.Collectors;
import java.security.cert.X509Certificate;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

/**
 * Proxy troubleshooting tool. Reads config from proxytest.properties.
 *
 * Usage:
 *   java ProxyTest                          # uses proxytest.properties in current dir
 *   java ProxyTest /path/to/config.properties
 *   java ProxyTest --help
 *
 * For SSL debug:
 *   java -Djavax.net.debug=ssl,handshake ProxyTest
 */
public class ProxyTest {

    static final Map<String, String> BUILTIN_TARGETS = new LinkedHashMap<>();
    static {
        BUILTIN_TARGETS.put("httpbin GET",      "https://httpbin.org/get");
        BUILTIN_TARGETS.put("httpbin IP",       "https://httpbin.org/ip");
        BUILTIN_TARGETS.put("httpbin headers",  "https://httpbin.org/headers");
        BUILTIN_TARGETS.put("ifconfig.me",      "https://ifconfig.me");
        BUILTIN_TARGETS.put("icanhazip.com",    "http://icanhazip.com");
        BUILTIN_TARGETS.put("google (HTTPS)",   "https://www.google.com");
        BUILTIN_TARGETS.put("google (HTTP)",    "http://www.google.com");
        BUILTIN_TARGETS.put("aws checkip",      "https://checkip.amazonaws.com");
        BUILTIN_TARGETS.put("cloudflare trace", "https://www.cloudflare.com/cdn-cgi/trace");
    }

    static SSLContext customSslContext = null;

    public static void main(String[] args) throws Exception {
        if (args.length == 1 && args[0].equals("--help")) {
            printUsage();
            return;
        }

        // Load config
        String configPath = args.length >= 1 ? args[0] : "proxytest.properties";
        Properties config = loadConfig(configPath);

        String proxyMode = config.getProperty("proxy.mode", "system").trim();
        String proxyHost = config.getProperty("proxy.host", "proxy.example.com").trim();
        int proxyPort = Integer.parseInt(config.getProperty("proxy.port", "9443").trim());
        int connectTimeout = Integer.parseInt(config.getProperty("timeout.connect", "10").trim());
        int requestTimeout = Integer.parseInt(config.getProperty("timeout.request", "30").trim());
        String method = config.getProperty("http.method", "GET").trim().toUpperCase();
        String body = config.getProperty("http.body", "").trim();
        boolean showFullBody = Boolean.parseBoolean(config.getProperty("show.full.body", "false").trim());
        boolean verbose = Boolean.parseBoolean(config.getProperty("verbose", "true").trim());
        String trustStorePath = config.getProperty("truststore.path", "").trim();
        String trustStorePassword = config.getProperty("truststore.password", "changeit").trim();
        String nonProxyHosts = config.getProperty("nonProxyHosts", "").trim();

        Set<String> skip = Arrays.stream(config.getProperty("skip", "").split(","))
                .map(String::trim).filter(s -> !s.isEmpty())
                .collect(Collectors.toSet());

        // Resolve targets
        Map<String, String> targets = resolveTargets(config.getProperty("targets", "builtin").trim());

        // Apply nonProxyHosts to JVM if set in config and not already set
        if (!nonProxyHosts.isEmpty()) {
            if (System.getProperty("http.nonProxyHosts") == null) {
                System.setProperty("http.nonProxyHosts", nonProxyHosts);
            }
            if (System.getProperty("https.nonProxyHosts") == null) {
                System.setProperty("https.nonProxyHosts", nonProxyHosts);
            }
        }

        // Header
        System.out.println("============================================");
        System.out.println("  Proxy Diagnostics Tool");
        System.out.println("============================================");
        System.out.println("Config:  " + configPath);
        System.out.println("Mode:    " + proxyMode);

        // Setup custom trust store if configured
        if (!trustStorePath.isEmpty()) {
            Path tsPath = Path.of(trustStorePath);
            if (Files.exists(tsPath)) {
                try {
                    KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
                    try (FileInputStream fis = new FileInputStream(tsPath.toFile())) {
                        ks.load(fis, trustStorePassword.toCharArray());
                    }
                    TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
                    tmf.init(ks);
                    customSslContext = SSLContext.getInstance("TLS");
                    customSslContext.init(null, tmf.getTrustManagers(), null);
                    System.out.println("Trust:   " + trustStorePath + " (" + ks.size() + " entries)");
                } catch (Exception e) {
                    System.err.println("WARN     Failed to load trust store: " + e.getMessage());
                    System.err.println("         Falling back to Java default trust store.");
                }
            } else {
                System.out.println("Trust:   " + trustStorePath + " (NOT FOUND - using Java default)");
            }
        }

        // Determine effective proxy
        String effectiveHost = null;
        int effectivePort = 0;

        switch (proxyMode) {
            case "system":
                effectiveHost = System.getProperty("https.proxyHost",
                        System.getProperty("http.proxyHost", proxyHost));
                String portStr = System.getProperty("https.proxyPort",
                        System.getProperty("http.proxyPort", String.valueOf(proxyPort)));
                effectivePort = Integer.parseInt(portStr);
                System.out.println("Proxy:   " + effectiveHost + ":" + effectivePort + " (from system props or config fallback)");
                break;
            case "none":
                System.out.println("Proxy:   DIRECT (no proxy)");
                break;
            default:
                effectiveHost = proxyHost;
                effectivePort = proxyPort;
                System.out.println("Proxy:   " + effectiveHost + ":" + effectivePort);
                break;
        }

        System.out.println("Method:  " + method);
        System.out.println("Java:    " + System.getProperty("java.version"));
        SSLContext defaultSsl = customSslContext != null ? customSslContext : SSLContext.getDefault();
        System.out.println("TLS:     " + defaultSsl.getProtocol());
        System.out.println("Targets: " + targets.size());
        System.out.println();

        // Dump JVM proxy properties
        if (verbose) {
            System.out.println("--- JVM Proxy Properties ---");
            String[][] props = {
                {"http.proxyHost", "http.proxyPort"},
                {"https.proxyHost", "https.proxyPort"},
                {"http.nonProxyHosts", null},
                {"https.nonProxyHosts", null},
                {"socksProxyHost", "socksProxyPort"},
            };
            boolean anySet = false;
            for (String[] pair : props) {
                String val = System.getProperty(pair[0]);
                if (val != null) {
                    anySet = true;
                    String line = "  " + pair[0] + " = " + val;
                    if (pair[1] != null) {
                        String port = System.getProperty(pair[1], "(not set)");
                        line += ", " + pair[1] + " = " + port;
                    }
                    System.out.println(line);
                }
            }
            if (!anySet) System.out.println("  (none set)");
            System.out.println();

            // Show which targets will bypass the proxy
            String npHosts = System.getProperty("http.nonProxyHosts", "");
            if (!npHosts.isEmpty()) {
                System.out.println("--- nonProxyHosts Check ---");
                for (Map.Entry<String, String> entry : targets.entrySet()) {
                    String host = URI.create(entry.getValue()).getHost();
                    boolean bypassed = matchesNonProxyHosts(host, npHosts);
                    System.out.println("  " + (bypassed ? "DIRECT" : "PROXY ") + "  " + host + " (" + entry.getKey() + ")");
                }
                System.out.println();
            }
        }

        // Phases only run when we have a proxy
        if (effectiveHost != null) {
            if (!skip.contains("dns")) {
                System.out.println("--- Phase 1: DNS Resolution ---");
                try {
                    long t0 = System.currentTimeMillis();
                    var addrs = java.net.InetAddress.getAllByName(effectiveHost);
                    System.out.println("OK       Resolved " + effectiveHost + " in " + (System.currentTimeMillis() - t0) + " ms");
                    for (var addr : addrs) System.out.println("  -> " + addr.getHostAddress());
                } catch (Exception e) {
                    System.err.println("FAIL     " + e.getMessage());
                }
                System.out.println();
            }

            if (!skip.contains("tcp")) {
                System.out.println("--- Phase 2: TCP Connect to Proxy ---");
                try {
                    long t0 = System.currentTimeMillis();
                    Socket sock = new Socket();
                    sock.connect(new InetSocketAddress(effectiveHost, effectivePort), connectTimeout * 1000);
                    System.out.println("OK       TCP connect in " + (System.currentTimeMillis() - t0) + " ms");
                    System.out.println("Local:   " + sock.getLocalSocketAddress());
                    System.out.println("Remote:  " + sock.getRemoteSocketAddress());
                    sock.close();
                } catch (IOException e) {
                    System.err.println("FAIL     " + e.getClass().getSimpleName() + ": " + e.getMessage());
                }
                System.out.println();
            }

            if (!skip.contains("tls")) {
                System.out.println("--- Phase 3: TLS Handshake to Proxy ---");

                // First, probe to see if the proxy speaks TLS at all
                boolean proxyHasTls = false;
                try {
                    X509TrustManager trustAll = new X509TrustManager() {
                        public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
                        public void checkClientTrusted(X509Certificate[] c, String t) {}
                        public void checkServerTrusted(X509Certificate[] c, String t) {}
                    };
                    SSLContext probeCtx = SSLContext.getInstance("TLS");
                    probeCtx.init(null, new javax.net.ssl.TrustManager[]{trustAll}, null);
                    SSLSocket probeSock = (SSLSocket) probeCtx.getSocketFactory().createSocket(effectiveHost, effectivePort);
                    probeSock.setSoTimeout(connectTimeout * 1000);
                    probeSock.startHandshake();
                    java.security.cert.Certificate[] certs = probeSock.getSession().getPeerCertificates();
                    probeSock.close();
                    proxyHasTls = true;

                    System.out.println("Certs presented by proxy (" + certs.length + "):");
                    for (int i = 0; i < certs.length; i++) {
                        if (certs[i] instanceof X509Certificate) {
                            X509Certificate x = (X509Certificate) certs[i];
                            String label = (i == 0) ? "leaf" : (i == certs.length - 1) ? "root" : "intermediate";
                            System.out.println("  [" + i + "] (" + label + ") Subject: " + x.getSubjectX500Principal());
                            System.out.println("       Issuer:  " + x.getIssuerX500Principal());
                            System.out.println("       Expires: " + x.getNotAfter());
                        }
                    }
                    System.out.println();
                } catch (Exception e) {
                    System.out.println("OK       Proxy is plain HTTP (does not speak TLS). This is normal.");
                }

                // If proxy speaks TLS, verify against the configured trust store
                if (proxyHasTls) {
                    try {
                        SSLSocketFactory sf = customSslContext != null
                                ? customSslContext.getSocketFactory()
                                : (SSLSocketFactory) SSLSocketFactory.getDefault();
                        long t0 = System.currentTimeMillis();
                        SSLSocket sslSock = (SSLSocket) sf.createSocket(effectiveHost, effectivePort);
                        sslSock.setSoTimeout(connectTimeout * 1000);
                        sslSock.startHandshake();
                        System.out.println("OK       TLS verified in " + (System.currentTimeMillis() - t0) + " ms");
                        System.out.println("Proto:   " + sslSock.getSession().getProtocol());
                        System.out.println("Cipher:  " + sslSock.getSession().getCipherSuite());
                        System.out.println("Peer:    " + sslSock.getSession().getPeerPrincipal());
                        sslSock.close();
                    } catch (Exception e) {
                        System.err.println("FAIL     Trust store does not trust the proxy's certificate.");
                        System.err.println("         " + e.getClass().getSimpleName() + ": " + e.getMessage());
                        System.err.println("         Import the root CA shown above into your trust store:");
                        System.err.println("         ./import-certs.sh <ca-bundle.pem> ./cacerts");
                    }
                }
                System.out.println();
            }
        }

        // Phase 4: Raw HTTP CONNECT tunnel test
        if (effectiveHost != null && !skip.contains("connect")) {
            System.out.println("--- Phase 4: Raw HTTP CONNECT Tunnel ---");
            try (Socket sock = new Socket()) {
                sock.connect(new InetSocketAddress(effectiveHost, effectivePort), connectTimeout * 1000);
                sock.setSoTimeout(requestTimeout * 1000);
                String connectReq = "CONNECT httpbin.org:443 HTTP/1.1\r\nHost: httpbin.org:443\r\n\r\n";
                long t0 = System.currentTimeMillis();
                sock.getOutputStream().write(connectReq.getBytes(StandardCharsets.US_ASCII));
                sock.getOutputStream().flush();
                // Read until we get a full status line
                byte[] buf = new byte[1024];
                int total = 0;
                while (total < buf.length) {
                    int n = sock.getInputStream().read(buf, total, buf.length - total);
                    if (n == -1) break;
                    total += n;
                    // Check if we have at least a complete status line
                    String partial = new String(buf, 0, total, StandardCharsets.US_ASCII);
                    if (partial.contains("\n")) break;
                }
                long t1 = System.currentTimeMillis();
                if (total > 0) {
                    String response = new String(buf, 0, total, StandardCharsets.US_ASCII);
                    String statusLine = response.split("\r?\n")[0];
                    System.out.println("OK       " + statusLine + " (" + (t1 - t0) + " ms)");
                } else {
                    System.err.println("FAIL     Proxy closed connection without response");
                }
            } catch (Exception e) {
                System.err.println("FAIL     " + e.getClass().getSimpleName() + ": " + e.getMessage());
                System.err.println("         Proxy may not support CONNECT method on this port.");
            }
            System.out.println();
        }

        // Phase 5: HTTP requests
        if (!skip.contains("http")) {
            System.out.println("--- Phase 5: HTTP Requests ---");
            System.out.println();
            int pass = 0, fail = 0;

            // Build nonProxyHosts-aware proxy selector
            final String finalEffectiveHost = effectiveHost;
            final int finalEffectivePort = effectivePort;
            final String npHosts = System.getProperty("http.nonProxyHosts", "");

            for (Map.Entry<String, String> entry : targets.entrySet()) {
                System.out.println("[" + entry.getKey() + "] " + entry.getValue());

                String targetHost = URI.create(entry.getValue()).getHost();
                boolean bypassed = !npHosts.isEmpty() && matchesNonProxyHosts(targetHost, npHosts);
                String useProxyHost = (proxyMode.equals("none") || bypassed) ? null : finalEffectiveHost;

                if (bypassed) {
                    System.out.println("  INFO   Bypassing proxy (nonProxyHosts match)");
                }

                boolean ok = runRequest(useProxyHost, finalEffectivePort,
                        entry.getValue(), method, body,
                        connectTimeout, requestTimeout, showFullBody);
                if (ok) pass++; else fail++;
                System.out.println();
            }

            System.out.println("============================================");
            System.out.println("  Results: " + pass + " passed, " + fail + " failed / " + (pass + fail));
            System.out.println("============================================");
        }
    }

    static boolean matchesNonProxyHosts(String host, String nonProxyHosts) {
        String[] patterns = nonProxyHosts.split("\\|");
        for (String pattern : patterns) {
            pattern = pattern.trim();
            if (pattern.isEmpty()) continue;
            // Convert glob to regex: *.example.com -> .*\.example\.com
            String regex = pattern
                    .replace(".", "\\.")
                    .replace("*", ".*");
            if (host.matches(regex)) return true;
        }
        return false;
    }

    static Properties loadConfig(String path) {
        Properties props = new Properties();
        Path p = Path.of(path);
        if (Files.exists(p)) {
            try (FileInputStream fis = new FileInputStream(p.toFile())) {
                props.load(fis);
                System.out.println("Loaded config: " + p.toAbsolutePath());
            } catch (IOException e) {
                System.err.println("Warning: Could not read " + path + ": " + e.getMessage());
            }
        } else {
            System.out.println("No config file found at " + p.toAbsolutePath());
            System.out.println("Using defaults. Create proxytest.properties to customize.");
        }
        return props;
    }

    static Map<String, String> resolveTargets(String targetSpec) {
        Map<String, String> result = new LinkedHashMap<>();
        if (targetSpec.equalsIgnoreCase("builtin")) {
            result.putAll(BUILTIN_TARGETS);
        } else {
            String[] urls = targetSpec.split(",");
            for (int i = 0; i < urls.length; i++) {
                String url = urls[i].trim();
                if (!url.isEmpty()) {
                    result.put("custom-" + (i + 1), url);
                }
            }
        }
        return result;
    }

    static boolean runRequest(String proxyHost, int proxyPort, String targetUrl,
                              String method, String body,
                              int connectTimeout, int requestTimeout, boolean showFullBody) {
        try {
            HttpClient.Builder clientBuilder = HttpClient.newBuilder()
                    .connectTimeout(Duration.ofSeconds(connectTimeout))
                    .followRedirects(HttpClient.Redirect.NORMAL);

            if (proxyHost != null) {
                clientBuilder.proxy(ProxySelector.of(new InetSocketAddress(proxyHost, proxyPort)));
            }

            if (customSslContext != null) {
                clientBuilder.sslContext(customSslContext);
            }

            HttpClient client = clientBuilder.build();

            HttpRequest.Builder requestBuilder = HttpRequest.newBuilder()
                    .uri(URI.create(targetUrl))
                    .timeout(Duration.ofSeconds(requestTimeout));

            switch (method) {
                case "GET":
                    requestBuilder.GET();
                    break;
                case "PUT":
                    requestBuilder.header("Content-Type", "application/json")
                            .PUT(HttpRequest.BodyPublishers.ofString(body));
                    break;
                case "POST":
                    requestBuilder.header("Content-Type", "application/json")
                            .POST(HttpRequest.BodyPublishers.ofString(body));
                    break;
                default:
                    System.err.println("  Unsupported method: " + method);
                    return false;
            }

            long start = System.currentTimeMillis();
            HttpResponse<String> response = client.send(requestBuilder.build(), HttpResponse.BodyHandlers.ofString());
            long elapsed = System.currentTimeMillis() - start;

            System.out.println("  OK     " + response.statusCode() + " (" + elapsed + " ms, " + response.body().length() + " bytes)");

            String respBody = response.body().trim();
            if (showFullBody || respBody.length() < 500) {
                for (String line : respBody.split("\r?\n")) {
                    System.out.println("         " + line);
                }
            }
            return true;

        } catch (Exception e) {
            System.err.println("  FAIL   " + e.getClass().getSimpleName() + ": " + e.getMessage());
            Throwable cause = e.getCause();
            while (cause != null) {
                System.err.println("         " + cause.getClass().getSimpleName() + ": " + cause.getMessage());
                cause = cause.getCause();
            }
            return false;
        }
    }

    static void printUsage() {
        System.out.println("Proxy Diagnostics Tool");
        System.out.println();
        System.out.println("Usage:");
        System.out.println("  java ProxyTest                             # uses proxytest.properties");
        System.out.println("  java ProxyTest /path/to/config.properties  # custom config");
        System.out.println("  java ProxyTest --help");
        System.out.println();
        System.out.println("Config file options:");
        System.out.println("  proxy.mode          = system | none | config");
        System.out.println("  proxy.host          = hostname");
        System.out.println("  proxy.port          = port");
        System.out.println("  truststore.path     = /path/to/cacerts  (blank = Java default)");
        System.out.println("  truststore.password  = password");
        System.out.println("  nonProxyHosts       = *.example.com|localhost  (pipe-delimited)");
        System.out.println("  timeout.connect     = seconds");
        System.out.println("  timeout.request     = seconds");
        System.out.println("  http.method         = GET | PUT | POST");
        System.out.println("  http.body           = request body for PUT/POST");
        System.out.println("  targets             = builtin | url1,url2,...");
        System.out.println("  skip                = dns,tcp,tls,connect,http");
        System.out.println("  show.full.body      = true | false");
        System.out.println("  verbose             = true | false");
        System.out.println();
        System.out.println("Built-in targets:");
        BUILTIN_TARGETS.forEach((name, url) -> System.out.println("  " + name + "  ->  " + url));
        System.out.println();
        System.out.println("For SSL debug:  java -Djavax.net.debug=ssl,handshake ProxyTest");
    }
}
