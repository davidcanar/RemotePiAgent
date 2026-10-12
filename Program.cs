using System.Collections.Concurrent;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;
using Konscious.Security.Cryptography;
using Microsoft.AspNetCore.Server.Kestrel.Core;

// ============================================================================
//  RemotePiAgent - secure HTTPS bridge to a local "pi" agent
//  Auth: username + password (Argon2id) + TOTP (RFC 6238, Authenticator)
//  Tokens: HMAC-SHA256 signed, short-lived. All attempts audit-logged.
// ============================================================================

var builder = WebApplication.CreateBuilder(args);
var cfg = builder.Configuration;

// Run correctly under the Windows Service Control Manager (no-op in console).
// Without this, SCM kills the process after 30 s (event 7009/7000, error 1053).
builder.Services.AddWindowsService(o => o.ServiceName = "RemotePiAgent");

// ------------------------------------------------------- CLI helper modes ---
// (run with --hash-password / --gen-totp / --gen-tokenkey to print a value and exit)
if (args.Length >= 2 && args[0] == "--hash-password")
{
    Console.WriteLine(Security.HashPassword(args[1]));
    return;
}
if (args.Length >= 1 && args[0] == "--test-totp")
{
    var secret = Convert.FromBase64String(args.Length > 1 ? args[1] : "PyxInyytvzf8zfl5pZd6rcA8SUs=");
    var step = args.Length > 2 ? long.Parse(args[2]) : DateTimeOffset.UtcNow.ToUnixTimeSeconds() / 30;
    var code = Security.TotpAt(secret, step);
    var counter = BitConverter.GetBytes(step);
    if (BitConverter.IsLittleEndian) Array.Reverse(counter);
    using var hmac = new HMACSHA1(secret);
    var hash = hmac.ComputeHash(counter);
    Console.WriteLine($"step={step} code={code} hmac={Convert.ToHexString(hash)}");
    return;
}
if (args.Length == 1)
{
    switch (args[0])
    {
        case "--gen-totp":
        {
            var secret = RandomNumberGenerator.GetBytes(20);
            Console.WriteLine("Base32 secret (paste into Authenticator as a manual key): " + Security.Base32Encode(secret));
            Console.WriteLine("Config value (Base64): " + Convert.ToBase64String(secret));
            return;
        }
        case "--gen-tokenkey":
            Console.WriteLine(Convert.ToHexString(RandomNumberGenerator.GetBytes(32)));
            return;
    }
}

// ---------------------------------------------------------------- config ---
var listenPort = cfg.GetValue<int>("ListenPort", 45454);
var certThumbprint = cfg["CertThumbprint"];
var piExecutable = cfg["PiExecutable"] ?? "pi";
var maxPromptLength = cfg.GetValue<int>("MaxPromptLength", 8000);
var commandTimeoutSeconds = cfg.GetValue<int>("CommandTimeoutSeconds", 600);
var maxOutputBytes = cfg.GetValue<int>("MaxOutputBytes", 1_000_000);
var tokenLifetimeMinutes = cfg.GetValue<int>("TokenLifetimeMinutes", 15);
var maxFailedLogins = cfg.GetValue<int>("MaxFailedLogins", 5);
var lockoutMinutes = cfg.GetValue<int>("LockoutMinutes", 15);

var adminUser = cfg["Auth:Username"]
    ?? throw new InvalidOperationException("Auth:Username is not configured.");
var passwordHash = cfg["Auth:PasswordHash"]
    ?? throw new InvalidOperationException("Auth:PasswordHash is not configured. Generate one with: RemotePiAgent --hash-password <password>");
var totpSecretB64 = cfg["Auth:TotpSecret"]
    ?? throw new InvalidOperationException("Auth:TotpSecret is not configured. Generate one with: RemotePiAgent --gen-totp");
var tokenKeyHex = cfg["Auth:TokenKey"]
    ?? throw new InvalidOperationException("Auth:TokenKey is not configured. Generate one with: RemotePiAgent --gen-tokenkey");

var tokenKey = Convert.FromHexString(tokenKeyHex);
var totpSecret = Convert.FromBase64String(totpSecretB64);

// ------------------------------------------------------------ rate limiting ---
var failedAttempts = new ConcurrentDictionary<string, (int Count, DateTimeOffset Until)>();

// ------------------------------------------------------------------- build ---
builder.Services.Configure<KestrelServerOptions>(o => o.AddServerHeader = false);
builder.WebHost.ConfigureKestrel(o =>
{
    o.Listen(IPAddress.Any, listenPort, lo =>
    {
        X509Certificate2? cert = null;
        if (!string.IsNullOrEmpty(certThumbprint))
        {
            try
            {
                using var store = new X509Store(StoreName.My, StoreLocation.LocalMachine);
                store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);
                cert = store.Certificates.Find(X509FindType.FindByThumbprint, certThumbprint, validOnly: false)
                        .OfType<X509Certificate2>().FirstOrDefault(c => c.HasPrivateKey);
            }
            catch { /* fall through to self-signed */ }
        }
        if (cert is null)
        {
            // Self-signed fallback - persisted to disk so the fingerprint stays
            // stable across restarts (browsers accept it once and keep trusting it).
            // Replace with a real cert via CertThumbprint when available.
            cert = Security.GetOrCreatePersistentSelfSignedCert(listenPort);
            Log.Audit($"WARNING: using persistent self-signed certificate on port {listenPort}");
        }
        lo.UseHttps(cert);
    });
});

builder.WebHost.ConfigureKestrel(o => o.Limits.MaxRequestBodySize = 64 * 1024);

var app = builder.Build();

// ------------------------------------------------------------------ auth ---
static string? GetBearer(HttpRequest req)
{
    var auth = req.Headers.Authorization.ToString();
    return auth.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase) ? auth[7..].Trim() : null;
}

static string ClientIp(HttpContext ctx) =>
    ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown";

app.MapPost("/api/auth/login", (LoginRequest login, HttpContext ctx) =>
{
    var ip = ClientIp(ctx);

    // lockout check
    if (failedAttempts.TryGetValue(ip, out var fa) && fa.Until > DateTimeOffset.UtcNow)
    {
        Log.Audit($"LOCKED-OUT login attempt from {ip}");
        return Results.Json(new { error = "Too many failed attempts. Try later." }, statusCode: 429);
    }

    var userOk = string.Equals(login.Username ?? "", adminUser, StringComparison.Ordinal);
    var passOk = userOk && Security.VerifyPassword(login.Password ?? "", passwordHash);
    var totpOk = passOk && Security.VerifyTotp(totpSecret, (login.Totp ?? "").Trim());

    if (!userOk || !passOk || !totpOk)
    {
        // constant-ish time: always verify a hash and a TOTP even for wrong users
        if (!passOk) Security.VerifyPassword(login.Password ?? "x", Security.DummyHash);
        if (!totpOk) Security.VerifyTotp(totpSecret, "000000");

        var (count, until) = failedAttempts.TryGetValue(ip, out var f) ? f : (0, DateTimeOffset.MinValue);
        count++;
        if (count >= maxFailedLogins)
        {
            failedAttempts[ip] = (0, DateTimeOffset.UtcNow.AddMinutes(lockoutMinutes));
            Log.Audit($"LOCKOUT triggered for {ip}");
        }
        else
        {
            failedAttempts[ip] = (count, until);
        }
        Log.Audit($"FAILED login (user:{userOk} pass:{passOk} totp:{totpOk}) from {ip}");
        return Results.Json(new { error = "Invalid credentials." }, statusCode: 401);
    }

    failedAttempts.TryRemove(ip, out _);
    var token = Security.IssueToken(tokenKey, adminUser, tokenLifetimeMinutes);
    Log.Audit($"LOGIN OK from {ip}");
    return Results.Ok(new { token, expiresInSeconds = tokenLifetimeMinutes * 60 });
});

// ------------------------------------------------------------ agent proxy ---
app.MapPost("/api/agent/run", async (RunRequest runReq, HttpContext ctx) =>
{
    if (GetBearer(ctx.Request) is not { } bearer)
    {
        return Results.Json(new { error = "Unauthorized." }, statusCode: 401);
    }
    if (!Security.ValidateToken(bearer, tokenKey, out string? err))
    {
        return Results.Json(new { error = err ?? "Unauthorized." }, statusCode: 401);
    }

    var prompt = (runReq.Prompt ?? "").Trim();
    if (prompt.Length == 0)
        return Results.Json(new { error = "Prompt is required." }, statusCode: 400);
    if (prompt.Length > maxPromptLength)
        return Results.Json(new { error = $"Prompt exceeds {maxPromptLength} characters." }, statusCode: 413);

    var ip = ClientIp(ctx);
    Log.Audit($"RUN from {ip} ({prompt.Length} chars)");

    try
    {
        var psi = new System.Diagnostics.ProcessStartInfo
        {
            FileName = piExecutable,
            ArgumentList = { prompt },   // passed as one argument - no shell interpolation
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            RedirectStandardInput = true,
            CreateNoWindow = true,
        };
        using var proc = System.Diagnostics.Process.Start(psi);
        if (proc is null)
            return Results.Json(new { error = "Failed to start pi agent." }, statusCode: 502);

        // pi reads the prompt from argv; close stdin so it never waits for input
        proc.StandardInput.Close();

        var stdoutTask = proc.StandardOutput.ReadToEndAsync();
        var stderrTask = proc.StandardError.ReadToEndAsync();

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(commandTimeoutSeconds));
        try
        {
            await proc.WaitForExitAsync(cts.Token);
        }
        catch (OperationCanceledException)
        {
            try { proc.Kill(entireProcessTree: true); } catch { }
            Log.Audit($"TIMEOUT kill of pi agent from {ip}");
            return Results.Json(new { error = "Command timed out and was killed." }, statusCode: 504);
        }

        var stdout = (await stdoutTask)[..Math.Min((await stdoutTask).Length, maxOutputBytes)];
        var stderr = (await stderrTask)[..Math.Min((await stderrTask).Length, maxOutputBytes)];
        Log.Audit($"DONE from {ip}, exit={proc.ExitCode}");
        return Results.Ok(new { exitCode = proc.ExitCode, stdout, stderr });
    }
    catch (Exception ex)
    {
        Log.Audit($"ERROR running pi agent from {ip}: {ex.GetType().Name}");
        return Results.Json(new { error = "Agent execution failed." }, statusCode: 500);
    }
});

// ------------------------------------------------------------------ misc ---
app.MapGet("/health", () => Results.Ok(new { status = "ok" }));

// --------------------------- static client page (for quick manual testing) ---
app.MapGet("/", () => Results.Text(Security.ClientPageHtml, "text/html"));

app.Run();

// ------------------------------------------------------------------ types ---
record LoginRequest(string? Username, string? Password, string? Totp);
record RunRequest(string? Prompt);

static class Log
{
    private static readonly object Gate = new();
    public static void Audit(string message)
    {
        var line = $"{DateTimeOffset.UtcNow:O} {message}";
        try
        {
            lock (Gate)
                File.AppendAllText(Path.Combine(AppContext.BaseDirectory, "audit.log"), line + Environment.NewLine);
        }
        catch { /* never crash the service for logging */ }
        Console.WriteLine(line);
    }
}

static class Security
{
    public const string DummyHash =
        "$RPIv1$AQIDBAUGBwgJCgsMDQ4PEA==$mNrMTZEOMMlCUbOIxDPCzIfV8cXBvXemRzHaEEd1aPA=";

    // ---- password hashing: Argon2id, random 16-byte salt, encoded string ----
    public static string HashPassword(string password)
    {
        var salt = RandomNumberGenerator.GetBytes(16);
        var hash = Argon2IdCompute(password, salt);
        return $"$RPIv1${Convert.ToBase64String(salt)}${Convert.ToBase64String(hash)}";
    }

    public static bool VerifyPassword(string password, string encoded)
    {
        try
        {
            var parts = encoded.Split('$');
            // "$RPIv1$<salt>$<hash>" -> ["", "RPIv1", salt, hash]
            if (parts.Length != 4 || parts[1] != "RPIv1") return false;
            var salt = Convert.FromBase64String(parts[2]);
            var expected = Convert.FromBase64String(parts[3]);
            var actual = Argon2IdCompute(password, salt);
            return CryptographicOperations.FixedTimeEquals(actual, expected);
        }
        catch { return false; }
    }

    private static byte[] Argon2IdCompute(string password, byte[] salt)
    {
        // Argon2id: strong defaults for a small admin service
        using var hasher = new Argon2id(Encoding.UTF8.GetBytes(password))
        {
            Salt = salt,
            MemorySize = 65536,   // 64 MB
            Iterations = 3,
            DegreeOfParallelism = 2,
        };
        return hasher.GetBytes(32);
    }

    // ---- TOTP (RFC 6238, 6 digits, 30 s step, +/- 1 step tolerance) ----
    public static bool VerifyTotp(byte[] secret, string code)
    {
        if (!Regex.IsMatch(code, @"^\d{6}$")) return false;
        var step = DateTimeOffset.UtcNow.ToUnixTimeSeconds() / 30;
        var span = new long[] { step, step - 1, step + 1 };
        foreach (var s in span)
        {
            if (TotpAt(secret, s) == code) return true;
        }
        return false;
    }

    public static string TotpAt(byte[] secret, long step)
    {
        var counter = BitConverter.GetBytes(step);
        if (BitConverter.IsLittleEndian) Array.Reverse(counter);
        using var hmac = new HMACSHA1(secret);
        var hash = hmac.ComputeHash(counter);
        var offset = hash[^1] & 0x0F;
        var bin = ((hash[offset] & 0x7F) << 24)
                | (hash[offset + 1] << 16)
                | (hash[offset + 2] << 8)
                | hash[offset + 3];
        return (bin % 1_000_000).ToString("D6");
    }

    // ---- HMAC-signed bearer tokens ----
    public static string IssueToken(byte[] key, string subject, int lifetimeMinutes)
    {
        var payload = Convert.ToBase64String(Encoding.UTF8.GetBytes(
            $"{subject}|{DateTimeOffset.UtcNow.AddMinutes(lifetimeMinutes).ToUnixTimeSeconds()}"));
        var sig = Convert.ToBase64String(Hmac(key, payload));
        return $"{payload}.{sig}";
    }

    public static bool ValidateToken(string token, byte[] key, out string? error)
    {
        error = null;
        try
        {
            var idx = token.LastIndexOf('.');
            if (idx < 0) { error = "Malformed token."; return false; }
            var payload = token[..idx];
            var sig = token[(idx + 1)..];
            var expected = Convert.ToBase64String(Hmac(key, payload));
            if (!CryptographicOperations.FixedTimeEquals(Encoding.UTF8.GetBytes(sig), Encoding.UTF8.GetBytes(expected)))
            {
                error = "Invalid token signature.";
                return false;
            }
            var parts = Encoding.UTF8.GetString(Convert.FromBase64String(payload)).Split('|');
            if (parts.Length != 2) { error = "Malformed token payload."; return false; }
            var expiry = long.Parse(parts[1]);
            if (DateTimeOffset.UtcNow.ToUnixTimeSeconds() > expiry) { error = "Token expired."; return false; }
            return true;
        }
        catch { error = "Malformed token."; return false; }
    }

    private static byte[] Hmac(byte[] key, string data)
    {
        using var h = new HMACSHA256(key);
        return h.ComputeHash(Encoding.UTF8.GetBytes(data));
    }

    // ---- misc ----
    public static string Base32Encode(byte[] data)
    {
        const string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        var sb = new StringBuilder();
        var bits = 0; var value = 0;
        foreach (var b in data)
        {
            value = (value << 8) | b;
            bits += 8;
            while (bits >= 5)
            {
                sb.Append(alphabet[(value >> (bits - 5)) & 31]);
                bits -= 5;
            }
        }
        if (bits > 0) sb.Append(alphabet[(value << (5 - bits)) & 31]);
        return sb.ToString();
    }

    public static X509Certificate2 CreateSelfSignedCert(int port)
    {
        var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=RemotePiAgent", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        // SANs so modern browsers validate the shape of the cert properly.
        var san = new SubjectAlternativeNameBuilder();
        san.AddDnsName("localhost");
        san.AddDnsName(Environment.MachineName);
        req.CertificateExtensions.Add(san.Build());
        var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddYears(5));
        return cert;
    }

    // Keeps one stable self-signed cert on disk: same fingerprint across restarts,
    // so browser certificate exceptions keep working after service restarts/updates.
    public static X509Certificate2 GetOrCreatePersistentSelfSignedCert(int port)
    {
        var pfxPath = Path.Combine(AppContext.BaseDirectory, "tls-selfsigned.pfx");
        if (File.Exists(pfxPath))
        {
            try
            {
                return X509CertificateLoader.LoadPkcs12(File.ReadAllBytes(pfxPath), null);
            }
            catch (Exception ex)
            {
                Log.Audit($"WARNING: could not load {pfxPath} ({ex.GetType().Name}); regenerating");
            }
        }
        var raw = CreateSelfSignedCert(port);            // exportable ephemeral key
        byte[] pfx = raw.Export(X509ContentType.Pfx);    // export BEFORE round-tripping
        // Windows Schannel requires a persistent private key property; ephemeral certs
        // fail the TLS handshake (Event 36869). Round-tripping through PFX fixes that.
        var cert = X509CertificateLoader.LoadPkcs12(pfx, null);
        File.WriteAllBytes(pfxPath, pfx);
        Log.Audit($"INFO: generated new persistent self-signed certificate at {pfxPath}");
        return cert;
    }

    public const string ClientPageHtml = """
<!DOCTYPE html>
<html>
<head><title>RemotePiAgent</title>
<style>
 body{font-family:Segoe UI,sans-serif;background:#1e1e2e;color:#cdd6f4;max-width:820px;margin:40px auto;padding:0 16px}
 input,textarea,button{background:#313244;color:#cdd6f4;border:1px solid #585b70;border-radius:6px;padding:8px;font-size:14px}
 button{cursor:pointer} button:hover{background:#45475a}
 pre{background:#11111b;padding:12px;border-radius:6px;white-space:pre-wrap;max-height:60vh;overflow:auto}
 h3{color:#89b4fa}
</style></head>
<body>
<h2>RemotePiAgent</h2>
<div id="auth">
 <h3>Login (password + Authenticator code)</h3>
 <input id="user" placeholder="username" style="width:200px"><br><br>
 <input id="pass" type="password" placeholder="password" style="width:200px"><br><br>
 <input id="totp" placeholder="6-digit code" style="width:120px" maxlength="6"><br><br>
 <button onclick="login()">Login</button>
</div>
<div id="agent" style="display:none">
 <h3>pi agent prompt</h3>
 <textarea id="prompt" rows="6" style="width:100%"></textarea><br><br>
 <button onclick="run()">Send to pi</button> <button onclick="logout()">Logout</button>
 <h3>Output</h3>
 <pre id="out">—</pre>
</div>
<script>
const $ = id => document.getElementById(id);
let token = '';
async function api(path, body) {
  const r = await fetch(path, { method:'POST', headers:{ 'Content-Type':'application/json', ...(token?{'Authorization':'Bearer '+token}:{}) }, body: JSON.stringify(body) });
  return { status: r.status, data: await r.json().catch(() => ({})) };
}
async function login() {
  const r = await api('/api/auth/login', { username: $('user').value, password: $('pass').value, totp: $('totp').value });
  if (r.data.token) { token = r.data.token; $('auth').style.display='none'; $('agent').style.display='block'; $('out').textContent='logged in'; }
  else $('out').textContent = 'Login failed: ' + (r.data.error || r.status);
}
async function run() {
  $('out').textContent = 'working...';
  const r = await api('/api/agent/run', { prompt: $('prompt').value });
  if (r.status === 401) { logout(); return; }
  $('out').textContent = `exit: ${r.data.exitCode ?? '-'}\n\n--- stdout ---\n${r.data.stdout || ''}\n--- stderr ---\n${r.data.stderr || ''}\n${r.data.error ? 'error: '+r.data.error : ''}`;
}
function logout() { token=''; $('agent').style.display='none'; $('auth').style.display='block'; }
</script>
</body>
</html>
""";
}
