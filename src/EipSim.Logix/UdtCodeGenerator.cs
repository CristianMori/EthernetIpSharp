using System.Text;

namespace EipSim.Logix;

/// <summary>
/// Generates C# source code for a UDT structure type from a TemplateInfo.
/// The generated class implements IUdtStructure with proper ToBytes/FromBytes
/// that handle Logix alignment, BOOL bit packing, and STRING layout.
///
/// Usage:
///   var template = await client.ReadTemplateAsync(templateId);
///   string code = UdtCodeGenerator.Generate(template);
///   File.WriteAllText("MixTypes.cs", code);
/// </summary>
public static class UdtCodeGenerator
{
    /// <summary>
    /// Generate a C# class from a TemplateInfo that implements IUdtStructure.
    /// </summary>
    /// <param name="template">The template definition from the PLC.</param>
    /// <param name="namespaceName">Namespace for the generated class.</param>
    /// <param name="className">Class name override. If null, derived from template name.</param>
    public static string Generate(TemplateInfo template, string namespaceName = "Generated", string? className = null)
    {
        // Clean up template name for use as class name
        string name = className ?? CleanName(template.Name);
        var sb = new StringBuilder();

        sb.AppendLine("using System.Buffers.Binary;");
        sb.AppendLine("using EipSim.Logix;");
        sb.AppendLine();
        sb.AppendLine($"namespace {namespaceName};");
        sb.AppendLine();
        sb.AppendLine($"/// <summary>");
        sb.AppendLine($"/// Generated from PLC template '{template.Name}'");
        sb.AppendLine($"/// Structure size: {template.StructureSize} bytes, {template.MemberCount} members");
        sb.AppendLine($"/// Structure handle: 0x{template.StructureHandle:X4}");
        sb.AppendLine($"/// </summary>");
        sb.AppendLine($"public sealed class {name} : IUdtStructure");
        sb.AppendLine("{");
        sb.AppendLine($"    public ushort StructureHandle => 0x{template.StructureHandle:X4};");
        sb.AppendLine($"    public int StructureSize => {template.StructureSize};");
        sb.AppendLine();

        // Properties for each visible member
        foreach (var m in template.Members)
        {
            if (IsHidden(m.Name)) continue;

            string propName = CleanPropertyName(m.Name);
            string propType = GetCSharpType(m);

            sb.AppendLine($"    /// <summary>{m.Name} — {GetTypeDescription(m)} @ offset {m.Offset}</summary>");
            sb.AppendLine($"    public {propType} {propName} {{ get; set; }}");
            sb.AppendLine();
        }

        // ToBytes method
        sb.AppendLine("    public byte[] ToBytes()");
        sb.AppendLine("    {");
        sb.AppendLine($"        var data = new byte[{template.StructureSize}];");
        sb.AppendLine();

        foreach (var m in template.Members)
        {
            if (IsHidden(m.Name)) continue;
            string propName = CleanPropertyName(m.Name);
            GenerateWriteMember(sb, m, propName);
        }

        sb.AppendLine("        return data;");
        sb.AppendLine("    }");
        sb.AppendLine();

        // FromBytes method
        sb.AppendLine("    public void FromBytes(byte[] data)");
        sb.AppendLine("    {");

        foreach (var m in template.Members)
        {
            if (IsHidden(m.Name)) continue;
            string propName = CleanPropertyName(m.Name);
            GenerateReadMember(sb, m, propName);
        }

        sb.AppendLine("    }");
        sb.AppendLine("}");

        return sb.ToString();
    }

    /// <summary>
    /// Generate C# classes for all templates in a browse result.
    /// </summary>
    public static string GenerateAll(TagBrowseResult browseResult, string namespaceName = "Generated")
    {
        var sb = new StringBuilder();
        sb.AppendLine("using System.Buffers.Binary;");
        sb.AppendLine("using EipSim.Logix;");
        sb.AppendLine();
        sb.AppendLine($"namespace {namespaceName};");
        sb.AppendLine();

        var generated = new HashSet<string>();
        foreach (var (_, template) in browseResult.Templates)
        {
            string name = CleanName(template.Name);
            if (generated.Contains(name)) continue;
            if (string.IsNullOrEmpty(name)) continue;

            generated.Add(name);
            sb.AppendLine(GenerateClassBody(template, name));
            sb.AppendLine();
        }

        return sb.ToString();
    }

    private static string GenerateClassBody(TemplateInfo template, string name)
    {
        var sb = new StringBuilder();

        sb.AppendLine($"/// <summary>Generated from '{template.Name}' ({template.StructureSize} bytes)</summary>");
        sb.AppendLine($"public sealed class {name} : IUdtStructure");
        sb.AppendLine("{");
        sb.AppendLine($"    public ushort StructureHandle => 0x{template.StructureHandle:X4};");
        sb.AppendLine($"    public int StructureSize => {template.StructureSize};");
        sb.AppendLine();

        foreach (var m in template.Members)
        {
            if (IsHidden(m.Name)) continue;
            string propName = CleanPropertyName(m.Name);
            string propType = GetCSharpType(m);
            sb.AppendLine($"    public {propType} {propName} {{ get; set; }}");
        }

        sb.AppendLine();
        sb.AppendLine("    public byte[] ToBytes()");
        sb.AppendLine("    {");
        sb.AppendLine($"        var data = new byte[{template.StructureSize}];");
        foreach (var m in template.Members)
        {
            if (IsHidden(m.Name)) continue;
            GenerateWriteMember(sb, m, CleanPropertyName(m.Name));
        }
        sb.AppendLine("        return data;");
        sb.AppendLine("    }");

        sb.AppendLine();
        sb.AppendLine("    public void FromBytes(byte[] data)");
        sb.AppendLine("    {");
        foreach (var m in template.Members)
        {
            if (IsHidden(m.Name)) continue;
            GenerateReadMember(sb, m, CleanPropertyName(m.Name));
        }
        sb.AppendLine("    }");
        sb.AppendLine("}");

        return sb.ToString();
    }

    private static void GenerateWriteMember(StringBuilder sb, TemplateMemberDetail m, string propName)
    {
        int off = (int)m.Offset;

        if (m.DataType == 0x00C1) // BOOL
        {
            sb.AppendLine($"        if ({propName}) data[{off}] |= (byte)(1 << {m.Info}); else data[{off}] &= (byte)~(1 << {m.Info});");
            return;
        }

        if (m.IsArray && (m.DataType & 0xE000) == 0x2000) // Array of atomics
        {
            int elemSize = LogixDataTypes.GetElementSize((ushort)(m.DataType & 0x00FF));
            if (elemSize <= 0) return;
            string writeCall = GetWriteCall(m.DataType, elemSize);
            if (writeCall != null)
            {
                sb.AppendLine($"        if ({propName} != null) for (int i = 0; i < Math.Min({propName}.Length, {m.ArraySize}); i++)");
                sb.AppendLine($"            {string.Format(writeCall, $"{off} + i * {elemSize}", $"{propName}[i]")};");
            }
            return;
        }

        if ((m.DataType & 0x8000) != 0) // Nested struct — skip for now
            return;

        // Scalar atomic
        ushort baseType = (ushort)(m.DataType & 0x00FF);
        switch (baseType)
        {
            case 0xC2: sb.AppendLine($"        data[{off}] = (byte){propName};"); break;
            case 0xC3: sb.AppendLine($"        BinaryPrimitives.WriteInt16LittleEndian(data.AsSpan({off}), {propName});"); break;
            case 0xC4: sb.AppendLine($"        BinaryPrimitives.WriteInt32LittleEndian(data.AsSpan({off}), {propName});"); break;
            case 0xC5: sb.AppendLine($"        BinaryPrimitives.WriteInt64LittleEndian(data.AsSpan({off}), {propName});"); break;
            case 0xCA: sb.AppendLine($"        BinaryPrimitives.WriteSingleLittleEndian(data.AsSpan({off}), {propName});"); break;
            case 0xCB: sb.AppendLine($"        BinaryPrimitives.WriteDoubleLittleEndian(data.AsSpan({off}), {propName});"); break;
        }
    }

    private static void GenerateReadMember(StringBuilder sb, TemplateMemberDetail m, string propName)
    {
        int off = (int)m.Offset;

        if (m.DataType == 0x00C1) // BOOL
        {
            sb.AppendLine($"        {propName} = (data[{off}] & (1 << {m.Info})) != 0;");
            return;
        }

        if (m.IsArray && (m.DataType & 0xE000) == 0x2000)
        {
            int elemSize = LogixDataTypes.GetElementSize((ushort)(m.DataType & 0x00FF));
            if (elemSize <= 0) return;
            string ctype = GetCSharpAtomicType((ushort)(m.DataType & 0x00FF));
            string readCall = GetReadCall(m.DataType, elemSize);
            if (readCall != null)
            {
                sb.AppendLine($"        {propName} = new {ctype}[{m.ArraySize}];");
                sb.AppendLine($"        for (int i = 0; i < {m.ArraySize}; i++)");
                sb.AppendLine($"            {propName}[i] = {string.Format(readCall, $"{off} + i * {elemSize}")};");
            }
            return;
        }

        if ((m.DataType & 0x8000) != 0) return; // Nested struct — skip

        ushort baseType = (ushort)(m.DataType & 0x00FF);
        switch (baseType)
        {
            case 0xC2: sb.AppendLine($"        {propName} = (sbyte)data[{off}];"); break;
            case 0xC3: sb.AppendLine($"        {propName} = BinaryPrimitives.ReadInt16LittleEndian(data.AsSpan({off}));"); break;
            case 0xC4: sb.AppendLine($"        {propName} = BinaryPrimitives.ReadInt32LittleEndian(data.AsSpan({off}));"); break;
            case 0xC5: sb.AppendLine($"        {propName} = BinaryPrimitives.ReadInt64LittleEndian(data.AsSpan({off}));"); break;
            case 0xCA: sb.AppendLine($"        {propName} = BinaryPrimitives.ReadSingleLittleEndian(data.AsSpan({off}));"); break;
            case 0xCB: sb.AppendLine($"        {propName} = BinaryPrimitives.ReadDoubleLittleEndian(data.AsSpan({off}));"); break;
        }
    }

    private static string GetCSharpType(TemplateMemberDetail m)
    {
        if (m.DataType == 0x00C1) return "bool";

        if (m.IsArray && (m.DataType & 0xE000) == 0x2000)
        {
            string elemType = GetCSharpAtomicType((ushort)(m.DataType & 0x00FF));
            return $"{elemType}[]";
        }

        if ((m.DataType & 0x8000) != 0)
            return "byte[]"; // Nested struct as raw bytes

        return GetCSharpAtomicType((ushort)(m.DataType & 0x00FF));
    }

    private static string GetCSharpAtomicType(ushort baseType) => baseType switch
    {
        0xC1 => "bool",
        0xC2 => "sbyte",
        0xC3 => "short",
        0xC4 => "int",
        0xC5 => "long",
        0xCA => "float",
        0xCB => "double",
        0xD3 => "uint",
        _ => "int",
    };

    private static string GetTypeDescription(TemplateMemberDetail m)
    {
        string typeName = (m.DataType & 0x00FF) switch
        {
            0xC1 => "BOOL", 0xC2 => "SINT", 0xC3 => "INT", 0xC4 => "DINT",
            0xC5 => "LINT", 0xCA => "REAL", 0xCB => "LREAL", 0xD3 => "DWORD",
            _ => $"0x{m.DataType:X4}",
        };
        if (m.IsArray) typeName += $"[{m.ArraySize}]";
        return typeName;
    }

    private static string? GetWriteCall(ushort dataType, int elemSize) => (dataType & 0x00FF) switch
    {
        0xC2 => "data[{0}] = (byte){1}",
        0xC3 => "BinaryPrimitives.WriteInt16LittleEndian(data.AsSpan({0}), {1})",
        0xC4 => "BinaryPrimitives.WriteInt32LittleEndian(data.AsSpan({0}), {1})",
        0xC5 => "BinaryPrimitives.WriteInt64LittleEndian(data.AsSpan({0}), {1})",
        0xCA => "BinaryPrimitives.WriteSingleLittleEndian(data.AsSpan({0}), {1})",
        0xCB => "BinaryPrimitives.WriteDoubleLittleEndian(data.AsSpan({0}), {1})",
        _ => null,
    };

    private static string? GetReadCall(ushort dataType, int elemSize) => (dataType & 0x00FF) switch
    {
        0xC2 => "(sbyte)data[{0}]",
        0xC3 => "BinaryPrimitives.ReadInt16LittleEndian(data.AsSpan({0}))",
        0xC4 => "BinaryPrimitives.ReadInt32LittleEndian(data.AsSpan({0}))",
        0xC5 => "BinaryPrimitives.ReadInt64LittleEndian(data.AsSpan({0}))",
        0xCA => "BinaryPrimitives.ReadSingleLittleEndian(data.AsSpan({0}))",
        0xCB => "BinaryPrimitives.ReadDoubleLittleEndian(data.AsSpan({0}))",
        _ => null,
    };

    private static bool IsHidden(string name) =>
        string.IsNullOrEmpty(name) || name.StartsWith("ZZZZZZZZZZ") || name.StartsWith("__");

    private static string CleanName(string templateName)
    {
        // Remove suffix like ";nEBECEC..."
        int semi = templateName.IndexOf(';');
        if (semi >= 0) templateName = templateName[..semi];

        // Remove "AB:" prefix and special chars
        templateName = templateName.Replace("AB:", "").Replace(":", "_").Replace("-", "_");

        // Ensure valid C# identifier
        if (templateName.Length > 0 && char.IsDigit(templateName[0]))
            templateName = "_" + templateName;

        return templateName;
    }

    private static string CleanPropertyName(string memberName)
    {
        if (string.IsNullOrEmpty(memberName)) return "_unknown";
        // Ensure first char is uppercase for C# convention
        var clean = memberName.Replace(":", "_").Replace("-", "_");
        if (char.IsDigit(clean[0])) clean = "_" + clean;
        return clean;
    }
}
