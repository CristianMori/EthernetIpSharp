// Catch-all CIP echo server (C# port of EthernetIPCpp/samples/cip_echo_server).
//
// Listens on TCP, handles RegisterSession, SendRRData (UCMM), and SendUnitData
// (Class 3 connected explicit). Every inbound CIP request that doesn't match a
// registered class is printed (service code, EPATH, hex data) and the reply
// carries `reply_bytes` bytes of incremental data (0, 1, 2, ...).
//
// Usage:  dotnet run -- [<bind>] [<tcp_port>] [<reply_bytes>]

using System.Net;
using EthernetIPSharp.Cip;
using EthernetIPSharp.Connections;
using EthernetIPSharp.Protocol;

string bind = args.Length > 0 ? args[0] : "0.0.0.0";
int    port = args.Length > 1 ? int.Parse(args[1]) : 44818;
int    replyBytes = args.Length > 2 ? int.Parse(args[2]) : 0;

var identity = new IdentityInfo
{
    VendorId      = 0x0001,
    DeviceType    = 0x000C,
    ProductCode   = 0xCAFE,
    MajorRevision = 1,
    MinorRevision = 0,
    SerialNumber  = 0xC1500001,
    ProductName   = "EthernetIPSharp CIP Echo Server",
    Status        = 0x0000,
};

var dispatcher = new CatchAllDispatcher();
long requestCount = 0;
dispatcher.SetHandler((in CatchAllRequest req) =>
{
    var n = Interlocked.Increment(ref requestCount);
    var p = req.Path;
    Console.Write($"[#{n}] svc=0x{req.ServiceCode:X2}  ");
    Console.Write($"class={(p.ClassId.HasValue ? "0x" + p.ClassId.Value.ToString("X2") : "-")}  ");
    Console.Write($"instance={(p.InstanceId?.ToString() ?? "-")}  ");
    Console.Write($"attribute={(p.AttributeId?.ToString() ?? "-")}  ");
    Console.Write($"element={(p.ElementId?.ToString() ?? "-")}  ");
    Console.Write($"conn_pt={(p.ConnectionPoint?.ToString() ?? "-")}  ");
    Console.Write($"symbol={p.SymbolicName ?? "-"}  ");
    var data = req.Data.Span;
    Console.Write($"data({data.Length})=");
    for (int i = 0; i < data.Length && i < 64; ++i)
        Console.Write($"{data[i]:X2} ");
    if (data.Length > 64) Console.Write("...");
    Console.WriteLine();

    var reply = new byte[replyBytes];
    for (int i = 0; i < replyBytes; ++i)
        reply[i] = (byte)i;
    return new CatchAllReply { Data = reply };
});

// Identity Object (Class 0x01) — for RegisterSession / ListIdentity.
var idClass = new CipClass(0x01, "Identity", revision: 1);
idClass.AddStandardInstanceServices();
var idInst = idClass.CreateInstance(1);
var aa = AttributeAccess.GetSingle | AttributeAccess.GetAll;
idInst.AddAttribute(CipAttribute.Create(1, CipDataType.Uint,  aa, identity.VendorId));
idInst.AddAttribute(CipAttribute.Create(2, CipDataType.Uint,  aa, identity.DeviceType));
idInst.AddAttribute(CipAttribute.Create(3, CipDataType.Uint,  aa, identity.ProductCode));
idInst.AddAttribute(new CipAttribute(4, CipDataType.Usint, aa,
    new byte[] { identity.MajorRevision, identity.MinorRevision }));
idInst.AddAttribute(CipAttribute.Create(5, CipDataType.Word,  aa, identity.Status));
idInst.AddAttribute(CipAttribute.Create(6, CipDataType.Udint, aa, identity.SerialNumber));
idInst.AddAttribute(CipAttribute.CreateShortString(7, aa, identity.ProductName));
dispatcher.RegisterClass(idClass);

// Connection Manager (Class 0x06) — required so the PLC can send Unconnected
// Send (svc 0x52) and Forward Open (svc 0x54). The CM's Unconnected Send
// handler unwraps the inner CIP request and calls back into our dispatcher;
// an inner request that doesn't match any registered class lands in the
// catch-all handler.
var connMgr = new ConnectionManagerObject();
connMgr.DispatchRequest = (svc, path, data) => dispatcher.Dispatch(svc, path, data);
dispatcher.RegisterClass(connMgr.CipClass);

var adapter = new EipAdapter(dispatcher, identity);

// Translate OT_conn_id (in incoming SendUnitData) → TO_conn_id (for the
// reply's ConnectedAddress item). Without this, Logix MSG ignores our Class
// 3 explicit replies as "not for me" and times out.
adapter.ConnectionIdLookup = otoTId =>
{
    var conn = connMgr.FindByOtoTId(otoTId);
    return conn?.TtoOConnectionId ?? 0;
};

await adapter.ListenAsync(IPAddress.Parse(bind), port);
Console.WriteLine("=== CIP Echo Server ===");
Console.WriteLine($"Listening on {bind}:{port}");
Console.WriteLine($"Reply payload: {replyBytes} byte(s)" +
    (replyBytes > 0 ? " of incremental data (0,1,2,...)" : " (empty)"));
Console.WriteLine("Every incoming CIP request will be printed below.");
Console.WriteLine("Ctrl+C to stop.\n");

using var cts = new CancellationTokenSource();
Console.CancelKeyPress += (_, e) => { e.Cancel = true; cts.Cancel(); };
try
{
    await Task.Delay(Timeout.Infinite, cts.Token);
}
catch (OperationCanceledException) { }
await adapter.DisposeAsync();
