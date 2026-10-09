using System.Buffers.Binary;
using System.Text;

namespace EthernetIPSharp.Logix;

/// <summary>
/// Binary save / restore for <see cref="TagDatabase"/> tag data.
///
/// <para><b>Semantic model.</b>  Saves tag <em>buffer contents</em> keyed by name;
/// does NOT persist the schema (templates, dims, symbol types) — those are
/// re-registered by application code at startup before <see cref="Load"/> is
/// called.  Load is tolerant: tags in the file that are unknown in the current
/// database are skipped; tags whose <see cref="Tag.TagType"/> disagrees with the
/// file are skipped; tags in the current database that are absent from the file
/// keep their as-registered zero-initialized buffers.  A <see cref="LoadResult"/>
/// reports both counts and per-tag warnings.</para>
///
/// <para><b>Cross-port byte compatibility.</b>  All ports (C#, C++, Rust, Python)
/// use the same little-endian binary layout so a file saved from one port loads
/// verbatim in another.  Version is encoded in the header; loaders reject
/// versions higher than what they understand.</para>
///
/// <para>Format v1:</para>
/// <code>
/// Header: magic "EIPS" (4 bytes) + version=1 (1 byte) + reserved (3 bytes = 0)
///
/// Controller tag section:
///   UDINT tag_count
///   For each tag:
///     UINT name_len; ASCII name[name_len]
///     UINT tag_type              // must match on load
///     UDINT data_size            // must match on load
///     BYTE data[data_size]
///
/// Program section:
///   UDINT program_count
///   For each program:
///     UINT name_len; ASCII name[name_len]
///     UDINT tag_count in this program
///     For each tag: (same layout as a controller tag)
/// </code>
/// </summary>
public static class TagDatabasePersistence
{
    private const uint Magic = 0x53_50_49_45; // "EIPS" little-endian.
    private const byte Version = 1;

    /// <summary>Report of what happened during <see cref="Load"/>.</summary>
    public sealed class LoadResult
    {
        public int TagsRestored { get; internal set; }
        public int TagsSkipped { get; internal set; }
        public List<string> Warnings { get; } = new();
    }

    /// <summary>Serialize the tag database's controller-scope and program-scope tag buffers.</summary>
    public static void Save(TagDatabase db, Stream stream)
    {
        Span<byte> header = stackalloc byte[8];
        BinaryPrimitives.WriteUInt32LittleEndian(header, Magic);
        header[4] = Version;
        header[5] = header[6] = header[7] = 0;
        stream.Write(header);

        var controllerTags = db.AllTags.ToList();
        WriteUdint(stream, (uint)controllerTags.Count);
        foreach (var tag in controllerTags) WriteTag(stream, tag);

        var programs = db.AllPrograms.ToList();
        WriteUdint(stream, (uint)programs.Count);
        foreach (var program in programs)
        {
            WriteString(stream, program.Name);
            var tags = program.AllTags.ToList();
            WriteUdint(stream, (uint)tags.Count);
            foreach (var tag in tags) WriteTag(stream, tag);
        }
    }

    /// <summary>Restore tag buffer contents from a stream written by <see cref="Save"/>.</summary>
    public static LoadResult Load(TagDatabase db, Stream stream)
    {
        var result = new LoadResult();

        Span<byte> header = stackalloc byte[8];
        ReadExact(stream, header);
        uint magic = BinaryPrimitives.ReadUInt32LittleEndian(header);
        if (magic != Magic)
            throw new InvalidDataException($"Not a TagDatabase snapshot: bad magic 0x{magic:X8}");
        byte version = header[4];
        if (version > Version)
            throw new InvalidDataException($"Snapshot version {version} is newer than this loader ({Version})");

        uint controllerTagCount = ReadUdint(stream);
        for (uint i = 0; i < controllerTagCount; i++)
            RestoreTagInto(stream, name => db.FindByName(name), result);

        uint programCount = ReadUdint(stream);
        for (uint i = 0; i < programCount; i++)
        {
            string programName = ReadString(stream);
            var program = db.FindProgram(programName);
            uint tagCount = ReadUdint(stream);
            for (uint j = 0; j < tagCount; j++)
            {
                if (program == null)
                {
                    // Program was in the file but hasn't been registered here —
                    // consume + drop each tag record so the stream stays aligned.
                    SkipTagRecord(stream);
                    result.TagsSkipped++;
                    result.Warnings.Add($"Program '{programName}' not registered — skipping tag records");
                    continue;
                }
                RestoreTagInto(stream, name => program.FindByName(name), result);
            }
        }

        return result;
    }

    private static void WriteTag(Stream stream, Tag tag)
    {
        WriteString(stream, tag.Name);
        WriteUint(stream, tag.TagType);
        WriteUdint(stream, (uint)tag.DataSize);
        stream.Write(tag.GetData());
    }

    private static void RestoreTagInto(Stream stream, Func<string, Tag?> lookup, LoadResult result)
    {
        string name = ReadString(stream);
        ushort tagType = ReadUint(stream);
        uint dataSize = ReadUdint(stream);

        // We must ALWAYS read the data bytes to keep the stream aligned, even
        // when we intend to skip the tag.  Rent a buffer to avoid a stackalloc
        // that would blow up on multi-KiB structure tags.
        var buffer = new byte[dataSize];
        ReadExact(stream, buffer);

        var tag = lookup(name);
        if (tag == null)
        {
            result.TagsSkipped++;
            result.Warnings.Add($"Tag '{name}' not registered — skipping");
            return;
        }
        if (tag.TagType != tagType)
        {
            result.TagsSkipped++;
            result.Warnings.Add($"Tag '{name}' tag_type mismatch (file=0x{tagType:X4}, current=0x{tag.TagType:X4}) — skipping");
            return;
        }
        if (tag.DataSize != (int)dataSize)
        {
            result.TagsSkipped++;
            result.Warnings.Add($"Tag '{name}' data_size mismatch (file={dataSize}, current={tag.DataSize}) — skipping");
            return;
        }

        // Silent restore — no ValueChanged fired during load.
        tag.SetDataSilent(buffer);
        result.TagsRestored++;
    }

    private static void SkipTagRecord(Stream stream)
    {
        _ = ReadString(stream);
        _ = ReadUint(stream);
        uint dataSize = ReadUdint(stream);
        var throwaway = new byte[dataSize];
        ReadExact(stream, throwaway);
    }

    // --- Little-endian primitives ---

    private static void WriteUint(Stream s, ushort v)
    {
        Span<byte> b = stackalloc byte[2];
        BinaryPrimitives.WriteUInt16LittleEndian(b, v);
        s.Write(b);
    }

    private static void WriteUdint(Stream s, uint v)
    {
        Span<byte> b = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32LittleEndian(b, v);
        s.Write(b);
    }

    private static void WriteString(Stream s, string value)
    {
        var bytes = Encoding.ASCII.GetBytes(value);
        WriteUint(s, (ushort)bytes.Length);
        s.Write(bytes);
    }

    private static ushort ReadUint(Stream s)
    {
        Span<byte> b = stackalloc byte[2];
        ReadExact(s, b);
        return BinaryPrimitives.ReadUInt16LittleEndian(b);
    }

    private static uint ReadUdint(Stream s)
    {
        Span<byte> b = stackalloc byte[4];
        ReadExact(s, b);
        return BinaryPrimitives.ReadUInt32LittleEndian(b);
    }

    private static string ReadString(Stream s)
    {
        ushort len = ReadUint(s);
        var bytes = new byte[len];
        ReadExact(s, bytes);
        return Encoding.ASCII.GetString(bytes);
    }

    private static void ReadExact(Stream s, Span<byte> buffer)
    {
        int read = 0;
        while (read < buffer.Length)
        {
            int n = s.Read(buffer.Slice(read));
            if (n == 0) throw new EndOfStreamException();
            read += n;
        }
    }
}
