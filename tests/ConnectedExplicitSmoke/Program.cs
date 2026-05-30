// Connected-explicit smoke test. Exercises both UCMM (SendExplicitAsync) and
// Class 3 connected explicit (OpenExplicitAsync + SendAsync) round-trips
// against an adapter that supports both (typically the StandardAdapterSample
// or CipEchoServer).
//
// Tests, in order:
//   1. UCMM GetAttributeSingle on Identity attr 7 — verifies UCMM path
//   2. Class 3 Forward Open
//   3. Class 3 GetAttributeSingle on Identity attr 7
//   4. Class 3 catch-all custom message (svc 0xCD class 0xDE inst 2 attr 156)
//      with a 7-DINT payload — verifies the unhandled-service path and
//      that the response payload is returned correctly.
//
//   dotnet run -- [host] [port]

using System.Net;
using EthernetIPSharp.Protocol;

string host = args.Length > 0 ? args[0]              : "127.0.0.1";
int    port = args.Length > 1 ? int.Parse(args[1])   : 44818;

static string IdentityName(ReadOnlyMemory<byte> data)
{
    if (data.IsEmpty) return "<empty>";
    var span = data.Span;
    int nameLen = span[0];
    return System.Text.Encoding.ASCII.GetString(
        span.Slice(1, Math.Min(nameLen, span.Length - 1)));
}

await using var scanner = new EipScanner();
try
{
    Console.WriteLine($"Connecting to {host}:{port} ...");
    await scanner.ConnectAsync(IPAddress.Parse(host), port);
    Console.WriteLine($"  session = 0x{scanner.SessionHandle:X8}");

    // ---- 1. UCMM ----
    Console.WriteLine("\n[UCMM] GetAttributeSingle(class=1, inst=1, attr=7) ...");
    var idPath = new byte[] { 0x20, 0x01, 0x24, 0x01, 0x30, 0x07 };
    var ucmm = await scanner.SendExplicitAsync(0x0E, idPath, Array.Empty<byte>());
    Console.WriteLine($"  status=0x{ucmm.Status.GeneralStatus:X2}  " +
                       $"data={ucmm.Data.Length} bytes  " +
                       $"ProductName=\"{IdentityName(ucmm.Data)}\"");

    // ---- 2/3. Class 3 ----
    Console.WriteLine("\n[Class3] Opening connection ...");
    await using var conn = await scanner.OpenExplicitAsync();
    Console.WriteLine("  open");

    var c3Id = await conn.SendAsync(0x0E, 0x01, 1, 7);
    Console.WriteLine($"  GetAttributeSingle(class=1, inst=1, attr=7): " +
                       $"status=0x{c3Id.Status.GeneralStatus:X2} " +
                       $"data={c3Id.Data.Length} bytes  " +
                       $"ProductName=\"{IdentityName(c3Id.Data)}\"");

    // ---- 4. Class 3 catch-all custom message ----
    Console.WriteLine("\n[Class3] Custom svc=0xCD class=0xDE inst=2 attr=156 with 28-byte payload ...");
    var payload = new byte[28];
    for (int i = 0; i < 7; ++i)
    {
        uint v = (uint)(1000 + i);
        BitConverter.GetBytes(v).CopyTo(payload, i * 4);
    }
    var c3Echo = await conn.SendAsync(0xCD, 0xDE, 2, 156, payload);
    Console.WriteLine($"  status=0x{c3Echo.Status.GeneralStatus:X2}  " +
                       $"reply data({c3Echo.Data.Length})=" +
                       string.Join(' ', c3Echo.Data.ToArray().Select(b => b.ToString("X2"))));

    Console.WriteLine("\nDone.");
    return 0;
}
catch (Exception ex)
{
    Console.Error.WriteLine($"ERROR: {ex.Message}");
    return 1;
}
