using System.ComponentModel;
using System.Reflection.Metadata;
using System.Reflection.Metadata.Ecma335;
using static System.Reflection.Metadata.Ecma335.MetadataTokens;
using DnSpyMcp.Core;
using DnSpyMcp.Models;
using ICSharpCode.Decompiler.CSharp;
using ICSharpCode.Decompiler.Metadata;
using ICSharpCode.Decompiler.TypeSystem;
using ModelContextProtocol.Server;

namespace DnSpyMcp.Tools.Analysis;

[McpServerToolType]
public class BreakpointTools
{
    private readonly AssemblyCache _cache;
    private readonly BreakpointRegistry _registry;

    public BreakpointTools(AssemblyCache cache, BreakpointRegistry registry)
    {
        _cache = cache;
        _registry = registry;
    }

    [McpServerTool(Name = "set_breakpoint"), Description("Set a virtual breakpoint at an IL offset in a method. Returns deep decoded context about that point.")]
    public BreakpointContext SetBreakpoint(
        [Description("Absolute or relative path to the .NET assembly")] string assemblyPath,
        [Description("Full type name (e.g. 'Namespace.ClassName')")] string typeName,
        [Description("Method name")] string methodName,
        [Description("IL byte offset (optional, defaults to 0)")] int? ilOffset = null)
    {
        try
        {
            var (decompiler, _) = _cache.GetOrLoad(assemblyPath);
            IMethod? method = null;
            foreach (var td in decompiler.TypeSystem.MainModule.TypeDefinitions)
            {
                if (td.FullName == typeName || td.Name == typeName)
                {
                    method = td.Methods.FirstOrDefault(m => m.Name == methodName);
                    if (method != null) break;
                }
            }
            if (method == null)
                throw new InvalidOperationException($"Method {typeName}.{methodName} not found in assembly");

            var bp = _registry.Add(assemblyPath, typeName, methodName, ilOffset);
            return BuildContext(bp, includeDecompile: true);
        }
        catch (Exception ex)
        {
            return new BreakpointContext { Id = "error", TypeName = typeName, MethodName = methodName, MethodSignature = $"ERROR: {ex.Message}" };
        }
    }

    [McpServerTool(Name = "list_breakpoints"), Description("List all virtual breakpoints, optionally filtered by assembly")]
    public List<BreakpointContext> ListBreakpoints(
        [Description("Optional: filter by assembly path")] string? assemblyPath = null)
    {
        var all = _registry.All();
        if (assemblyPath != null)
        {
            var abs = Path.GetFullPath(assemblyPath);
            all = all.Where(b => b.AssemblyPath == abs).ToList();
        }
        return all.Select(bp =>
        {
            try { return BuildContext(bp, includeDecompile: false); }
            catch (Exception ex)
            {
                return new BreakpointContext
                {
                    Id = bp.Id, AssemblyPath = bp.AssemblyPath,
                    TypeName = bp.TypeName, MethodName = bp.MethodName,
                    ILOffset = bp.ILOffset,
                    MethodSignature = $"ERROR: {ex.Message}",
                    CreatedAt = bp.CreatedAt
                };
            }
        }).ToList();
    }

    [McpServerTool(Name = "inspect_breakpoint"), Description("Inspect a breakpoint in full detail: decompiled source, IL context, stack state, and callers")]
    public BreakpointContext InspectBreakpoint(
        [Description("Breakpoint ID (e.g. 'bp001')")] string id)
    {
        var bp = _registry.Get(id);
        if (bp == null)
            return new BreakpointContext { Id = id, MethodSignature = $"ERROR: Breakpoint '{id}' not found" };
        try
        {
            return BuildContext(bp, includeDecompile: true);
        }
        catch (Exception ex)
        {
            return new BreakpointContext
            {
                Id = bp.Id, AssemblyPath = bp.AssemblyPath,
                TypeName = bp.TypeName, MethodName = bp.MethodName,
                ILOffset = bp.ILOffset, MethodSignature = $"ERROR: {ex.Message}",
                CreatedAt = bp.CreatedAt
            };
        }
    }

    [McpServerTool(Name = "clear_breakpoints"), Description("Clear breakpoints: by ID, by assembly, or all at once")]
    public object ClearBreakpoints(
        [Description("Optional: specific breakpoint ID to remove")] string? id = null,
        [Description("Optional: remove all breakpoints for this assembly path")] string? assemblyPath = null)
    {
        int removed;
        string message;
        if (id != null)
        {
            removed = _registry.Remove(id) ? 1 : 0;
            message = removed > 0 ? $"Removed breakpoint {id}" : $"Breakpoint {id} not found";
        }
        else if (assemblyPath != null)
        {
            removed = _registry.RemoveByAssembly(assemblyPath);
            message = $"Removed {removed} breakpoint(s) for assembly {assemblyPath}";
        }
        else
        {
            removed = _registry.RemoveAll();
            message = $"Cleared all {removed} breakpoint(s)";
        }
        return new { removed, message };
    }

    private BreakpointContext BuildContext(Breakpoint bp, bool includeDecompile = true)
    {
        var (decompiler, peFile) = _cache.GetOrLoad(bp.AssemblyPath);
        var meta = peFile.Metadata;

        IMethod? method = null;
        foreach (var td in decompiler.TypeSystem.MainModule.TypeDefinitions)
        {
            if (td.FullName == bp.TypeName || td.Name == bp.TypeName)
            {
                method = td.Methods.FirstOrDefault(m => m.Name == bp.MethodName);
                if (method != null) break;
            }
        }
        if (method == null)
            throw new InvalidOperationException($"Method {bp.TypeName}.{bp.MethodName} not found");

        int methodToken = GetToken(method.MetadataToken);
        var mdMethodHandle = MethodDefinitionHandle(methodToken & 0x00FFFFFF);
        var mdMethod = meta.GetMethodDefinition(mdMethodHandle);
        int rva = mdMethod.RelativeVirtualAddress;
        MethodBodyBlock? body = null;
        try { body = rva != 0 ? peFile.Reader.GetMethodBody(rva) : null; } catch { }

        var instructions = new List<ILInstruction>();
        if (body != null)
        {
            try
            {
                var ilReader = body.GetILReader();
                var ilBytes = ilReader.ReadBytes(ilReader.RemainingBytes);
                instructions = DecodeIL(ilBytes, meta);
            }
            catch { }
        }

        int targetIdx = bp.ILOffset.HasValue
            ? instructions.FindIndex(i => i.Offset >= bp.ILOffset.Value)
            : 0;
        if (targetIdx < 0) targetIdx = 0;

        var targetInstr = instructions.Count > 0
            ? instructions[Math.Min(targetIdx, instructions.Count - 1)]
            : null;
        var surrounding = instructions
            .Skip(Math.Max(0, targetIdx - 5))
            .Take(11)
            .ToList();

        var stackTypes = InferStackAtOffset(instructions, targetIdx);

        var callers = FindCallers(method, peFile).Take(10).ToList();

        string? src = null;
        if (includeDecompile)
        {
            try { src = decompiler.DecompileAsString(method.MetadataToken); } catch { }
        }

        string sig;
        try
        {
            sig = $"{method.ReturnType.Name} {method.FullName}({string.Join(", ", method.Parameters.Select(p => $"{p.Type.Name} {p.Name}"))})";
        }
        catch { sig = method.FullName; }

        int localCount = 0;
        if (body != null && !body.LocalSignature.IsNil)
        {
            try
            {
                var sig2 = meta.GetStandaloneSignature(body.LocalSignature);
                var br = meta.GetBlobReader(sig2.Signature);
                br.ReadByte(); 
                localCount = br.ReadCompressedInteger();
            }
            catch { }
        }

        return new BreakpointContext
        {
            Id = bp.Id,
            AssemblyPath = bp.AssemblyPath,
            TypeName = bp.TypeName,
            MethodName = bp.MethodName,
            ILOffset = bp.ILOffset,
            MethodSignature = sig,
            LocalCount = localCount,
            MaxStack = body?.MaxStack ?? 0,
            TargetInstruction = targetInstr,
            SurroundingIL = surrounding,
            InferredStackTypes = stackTypes,
            DecompiledSource = src,
            Callers = callers,
            CreatedAt = bp.CreatedAt,
        };
    }

    private static List<ILInstruction> DecodeIL(byte[] il, MetadataReader meta)
    {
        var result = new List<ILInstruction>();
        int i = 0;
        while (i < il.Length)
        {
            int offset = i;
            byte b = il[i++];
            string opName, operand = "", stackEffect = "";
            int operandSize = 0;

            if (b == 0xFE && i < il.Length)
            {
                byte b2 = il[i++];
                (opName, operandSize, stackEffect) = TwoByteOpCode(b2);
            }
            else
            {
                (opName, operandSize, stackEffect) = OneByteOpCode(b);
            }

            if (opName == "switch" && i + 4 <= il.Length)
            {
                uint n = BitConverter.ToUInt32(il, i);
                operand = $"({n} targets)";
                int totalSize = n < 10000 ? (int)(4 + n * 4) : 4;
                i += totalSize;
            }
            else if (operandSize > 0 && i + operandSize <= il.Length)
            {
                operand = FormatOperand(opName, il, i, operandSize, meta);
                i += operandSize;
            }

            result.Add(new ILInstruction(offset, opName, operand, stackEffect));
        }
        return result;
    }

    private static (string opName, int operandSize, string stackEffect) OneByteOpCode(byte b) => b switch
    {
        0x00 => ("nop", 0, ""),
        0x01 => ("break", 0, ""),
        0x02 => ("ldarg.0", 0, "push"),
        0x03 => ("ldarg.1", 0, "push"),
        0x04 => ("ldarg.2", 0, "push"),
        0x05 => ("ldarg.3", 0, "push"),
        0x06 => ("ldloc.0", 0, "push"),
        0x07 => ("ldloc.1", 0, "push"),
        0x08 => ("ldloc.2", 0, "push"),
        0x09 => ("ldloc.3", 0, "push"),
        0x0A => ("stloc.0", 0, "pop"),
        0x0B => ("stloc.1", 0, "pop"),
        0x0C => ("stloc.2", 0, "pop"),
        0x0D => ("stloc.3", 0, "pop"),
        0x0E => ("ldloc.s", 1, "push"),
        0x0F => ("stloc.s", 1, "pop"),
        0x10 => ("ldarga.s", 1, "push"),
        0x11 => ("starg.s", 1, "pop"),
        0x12 => ("ldloca.s", 1, "push"),
        0x13 => ("ldarg.s", 1, "push"),
        0x14 => ("ldnull", 0, "push null"),
        0x15 => ("ldc.i4.m1", 0, "push int"),
        0x16 => ("ldc.i4.0", 0, "push int"),
        0x17 => ("ldc.i4.1", 0, "push int"),
        0x18 => ("ldc.i4.2", 0, "push int"),
        0x19 => ("ldc.i4.3", 0, "push int"),
        0x1A => ("ldc.i4.4", 0, "push int"),
        0x1B => ("ldc.i4.5", 0, "push int"),
        0x1C => ("ldc.i4.6", 0, "push int"),
        0x1D => ("ldc.i4.7", 0, "push int"),
        0x1E => ("ldc.i4.8", 0, "push int"),
        0x1F => ("ldc.i4.s", 1, "push int"),
        0x20 => ("ldc.i4", 4, "push int"),
        0x21 => ("ldc.i8", 8, "push long"),
        0x22 => ("ldc.r4", 4, "push float"),
        0x23 => ("ldc.r8", 8, "push double"),
        0x25 => ("dup", 0, "push copy"),
        0x26 => ("pop", 0, "pop"),
        0x27 => ("jmp", 4, ""),
        0x28 => ("call", 4, "call"),
        0x29 => ("calli", 4, "call"),
        0x2A => ("ret", 0, "return"),
        0x2B => ("br.s", 1, "branch"),
        0x2C => ("brfalse.s", 1, "branch if false"),
        0x2D => ("brtrue.s", 1, "branch if true"),
        0x2E => ("beq.s", 1, "branch"),
        0x2F => ("bge.s", 1, "branch"),
        0x30 => ("bgt.s", 1, "branch"),
        0x31 => ("ble.s", 1, "branch"),
        0x32 => ("blt.s", 1, "branch"),
        0x33 => ("bne.un.s", 1, "branch"),
        0x34 => ("bge.un.s", 1, "branch"),
        0x35 => ("bgt.un.s", 1, "branch"),
        0x36 => ("ble.un.s", 1, "branch"),
        0x37 => ("blt.un.s", 1, "branch"),
        0x38 => ("br", 4, "branch"),
        0x39 => ("brfalse", 4, "branch if false"),
        0x3A => ("brtrue", 4, "branch if true"),
        0x3B => ("beq", 4, "branch"),
        0x3C => ("bge", 4, "branch"),
        0x3D => ("bgt", 4, "branch"),
        0x3E => ("ble", 4, "branch"),
        0x3F => ("blt", 4, "branch"),
        0x40 => ("bne.un", 4, "branch"),
        0x41 => ("bge.un", 4, "branch"),
        0x42 => ("bgt.un", 4, "branch"),
        0x43 => ("ble.un", 4, "branch"),
        0x44 => ("blt.un", 4, "branch"),
        0x45 => ("switch", 4, "branch table"),
        0x46 => ("ldind.i1", 0, "push"),
        0x47 => ("ldind.u1", 0, "push"),
        0x48 => ("ldind.i2", 0, "push"),
        0x49 => ("ldind.u2", 0, "push"),
        0x4A => ("ldind.i4", 0, "push"),
        0x4B => ("ldind.u4", 0, "push"),
        0x4C => ("ldind.i8", 0, "push"),
        0x4D => ("ldind.i", 0, "push"),
        0x4E => ("ldind.r4", 0, "push"),
        0x4F => ("ldind.r8", 0, "push"),
        0x50 => ("ldind.ref", 0, "push"),
        0x51 => ("stind.ref", 0, "pop"),
        0x52 => ("stind.i1", 0, "pop"),
        0x53 => ("stind.i2", 0, "pop"),
        0x54 => ("stind.i4", 0, "pop"),
        0x55 => ("stind.i8", 0, "pop"),
        0x56 => ("stind.r4", 0, "pop"),
        0x57 => ("stind.r8", 0, "pop"),
        0x58 => ("add", 0, ""),
        0x59 => ("sub", 0, ""),
        0x5A => ("mul", 0, ""),
        0x5B => ("div", 0, ""),
        0x5C => ("div.un", 0, ""),
        0x5D => ("rem", 0, ""),
        0x5E => ("rem.un", 0, ""),
        0x5F => ("and", 0, ""),
        0x60 => ("or", 0, ""),
        0x61 => ("xor", 0, ""),
        0x62 => ("shl", 0, ""),
        0x63 => ("shr", 0, ""),
        0x64 => ("shr.un", 0, ""),
        0x65 => ("neg", 0, ""),
        0x66 => ("not", 0, ""),
        0x67 => ("conv.i1", 0, ""),
        0x68 => ("conv.i2", 0, ""),
        0x69 => ("conv.i4", 0, ""),
        0x6A => ("conv.i8", 0, ""),
        0x6B => ("conv.r4", 0, ""),
        0x6C => ("conv.r8", 0, ""),
        0x6D => ("conv.u4", 0, ""),
        0x6E => ("conv.u8", 0, ""),
        0x6F => ("callvirt", 4, "call virtual"),
        0x70 => ("cpobj", 4, ""),
        0x71 => ("ldobj", 4, "push"),
        0x72 => ("ldstr", 4, "push string"),
        0x73 => ("newobj", 4, "push new"),
        0x74 => ("castclass", 4, ""),
        0x75 => ("isinst", 4, "push bool"),
        0x76 => ("conv.r.un", 0, ""),
        0x79 => ("unbox", 4, "push"),
        0x7A => ("throw", 0, ""),
        0x7B => ("ldfld", 4, "push field"),
        0x7C => ("ldflda", 4, "push field addr"),
        0x7D => ("stfld", 4, "pop+pop"),
        0x7E => ("ldsfld", 4, "push static field"),
        0x7F => ("stsfld", 4, "pop"),
        0x80 => ("stobj", 4, "pop"),
        0x8B => ("box", 4, "push boxed"),
        0x8C => ("newarr", 4, "push array"),
        0x8D => ("ldlen", 0, "push length"),
        0x8E => ("ldelema", 4, "push"),
        0x8F => ("ldelem.i1", 0, "push"),
        0x90 => ("ldelem.u1", 0, "push"),
        0x91 => ("ldelem.i2", 0, "push"),
        0x92 => ("ldelem.u2", 0, "push"),
        0x93 => ("ldelem.i4", 0, "push"),
        0x94 => ("ldelem.u4", 0, "push"),
        0x95 => ("ldelem.i8", 0, "push"),
        0x96 => ("ldelem.i", 0, "push"),
        0x97 => ("ldelem.r4", 0, "push"),
        0x98 => ("ldelem.r8", 0, "push"),
        0x99 => ("ldelem.ref", 0, "push"),
        0x9A => ("stelem.i", 0, "pop"),
        0x9B => ("stelem.i1", 0, "pop"),
        0x9C => ("stelem.i2", 0, "pop"),
        0x9D => ("stelem.i4", 0, "pop"),
        0x9E => ("stelem.i8", 0, "pop"),
        0x9F => ("stelem.r4", 0, "pop"),
        0xA0 => ("stelem.r8", 0, "pop"),
        0xA1 => ("stelem.ref", 0, "pop+pop+pop"),
        0xA2 => ("ldelem", 4, "push element"),
        0xA3 => ("stelem", 4, "pop"),
        0xA4 => ("unbox.any", 4, "push"),
        0xB3 => ("conv.ovf.i1", 0, ""),
        0xB4 => ("conv.ovf.u1", 0, ""),
        0xB5 => ("conv.ovf.i2", 0, ""),
        0xB6 => ("conv.ovf.u2", 0, ""),
        0xB7 => ("conv.ovf.i4", 0, ""),
        0xB8 => ("conv.ovf.u4", 0, ""),
        0xB9 => ("conv.ovf.i8", 0, ""),
        0xBA => ("conv.ovf.u8", 0, ""),
        0xC2 => ("refanyval", 4, "push"),
        0xC3 => ("ckfinite", 0, ""),
        0xC6 => ("mkrefany", 4, "push"),
        0xD0 => ("ldtoken", 4, "push"),
        0xD1 => ("conv.u2", 0, ""),
        0xD2 => ("conv.u1", 0, ""),
        0xD3 => ("conv.i", 0, ""),
        0xD4 => ("conv.ovf.i", 0, ""),
        0xD5 => ("conv.ovf.u", 0, ""),
        0xD6 => ("add.ovf", 0, ""),
        0xD7 => ("add.ovf.un", 0, ""),
        0xD8 => ("mul.ovf", 0, ""),
        0xD9 => ("mul.ovf.un", 0, ""),
        0xDA => ("sub.ovf", 0, ""),
        0xDB => ("sub.ovf.un", 0, ""),
        0xDC => ("endfinally", 0, ""),
        0xDD => ("leave", 4, "branch"),
        0xDE => ("leave.s", 1, "branch"),
        0xDF => ("stind.i", 0, "pop"),
        0xE0 => ("conv.u", 0, ""),
        _ => ($"0x{b:X2}", 0, "")
    };

    private static (string opName, int operandSize, string stackEffect) TwoByteOpCode(byte b) => b switch
    {
        0x01 => ("ceq", 0, "push bool"),
        0x02 => ("cgt", 0, "push bool"),
        0x03 => ("cgt.un", 0, "push bool"),
        0x04 => ("clt", 0, "push bool"),
        0x05 => ("clt.un", 0, "push bool"),
        0x06 => ("ldftn", 4, "push"),
        0x07 => ("ldvirtftn", 4, "push"),
        0x09 => ("ldarg", 2, "push"),
        0x0A => ("ldarga", 2, "push"),
        0x0B => ("starg", 2, "pop"),
        0x0C => ("ldloc", 2, "push"),
        0x0D => ("ldloca", 2, "push"),
        0x0E => ("stloc", 2, "pop"),
        0x0F => ("localloc", 0, "push"),
        0x11 => ("endfilter", 0, ""),
        0x12 => ("unaligned", 1, ""),
        0x13 => ("volatile", 0, ""),
        0x14 => ("tail", 0, ""),
        0x15 => ("initobj", 4, ""),
        0x16 => ("constrained", 4, ""),
        0x17 => ("cpblk", 0, ""),
        0x18 => ("initblk", 0, ""),
        0x1A => ("rethrow", 0, ""),
        0x1C => ("sizeof", 4, "push"),
        0x1D => ("refanytype", 0, "push"),
        0x1E => ("readonly", 0, ""),
        _ => ($"0xFE{b:X2}", 0, "")
    };

    private static string FormatOperand(string opName, byte[] il, int pos, int size, MetadataReader meta)
    {
        try
        {
            if (size == 1) return $"0x{il[pos]:X2}";
            if (size == 2) return $"0x{BitConverter.ToUInt16(il, pos):X4}";
            if (size == 8) return BitConverter.ToInt64(il, pos).ToString();

            int raw = BitConverter.ToInt32(il, pos);
            int tableId = (raw >> 24) & 0xFF;
            int row = raw & 0x00FFFFFF;

            switch (opName)
            {
                case "ldstr":
                {
                    try
                    {
                        var str = meta.GetUserString(UserStringHandle(row));
                        var truncated = str.Length > 60 ? str[..60] + "..." : str;
                        return $"\"{truncated}\"";
                    }
                    catch { return $"0x{raw:X8}"; }
                }
                case "call":
                case "callvirt":
                case "newobj":
                case "ldftn":
                case "ldvirtftn":
                {
                    try
                    {
                        if (tableId == 0x06)
                        {
                            var mh = MethodDefinitionHandle(row);
                            return meta.GetString(meta.GetMethodDefinition(mh).Name);
                        }
                        else if (tableId == 0x0A)
                        {
                            var mr = meta.GetMemberReference(MemberReferenceHandle(row));
                            string parentName = "";
                            if (mr.Parent.Kind == HandleKind.TypeReference)
                                parentName = meta.GetString(meta.GetTypeReference((TypeReferenceHandle)mr.Parent).Name) + "::";
                            return parentName + meta.GetString(mr.Name);
                        }
                        else if (tableId == 0x2B)
                        {
                            return $"methodspec[{row}]";
                        }
                    }
                    catch { }
                    return $"0x{raw:X8}";
                }
                case "ldfld":
                case "ldflda":
                case "stfld":
                case "ldsfld":
                case "stsfld":
                {
                    try
                    {
                        if (tableId == 0x04)
                            return meta.GetString(meta.GetFieldDefinition(FieldDefinitionHandle(row)).Name);
                        else if (tableId == 0x0A)
                            return meta.GetString(meta.GetMemberReference(MemberReferenceHandle(row)).Name);
                    }
                    catch { }
                    return $"0x{raw:X8}";
                }
                case "castclass":
                case "isinst":
                case "unbox":
                case "unbox.any":
                case "box":
                case "newarr":
                case "initobj":
                case "constrained":
                case "cpobj":
                case "ldobj":
                case "stobj":
                {
                    try
                    {
                        if (tableId == 0x01)
                            return meta.GetString(meta.GetTypeReference(TypeReferenceHandle(row)).Name);
                        else if (tableId == 0x02)
                            return meta.GetString(meta.GetTypeDefinition(TypeDefinitionHandle(row)).Name);
                    }
                    catch { }
                    return $"0x{raw:X8}";
                }
                default:
                    if (opName.StartsWith("br") || opName.StartsWith("b") || opName == "leave")
                        return $"IL_{raw:X4}";
                    return $"0x{raw:X8}";
            }
        }
        catch
        {
            try { return size <= 4 ? $"0x{BitConverter.ToInt32(il, pos):X8}" : "?"; } catch { return "?"; }
        }
    }

    private static List<string> InferStackAtOffset(List<ILInstruction> instructions, int targetIdx)
    {
        var stack = new Stack<string>();
        for (int i = 0; i < targetIdx && i < instructions.Count; i++)
        {
            var instr = instructions[i];
            try
            {
                switch (instr.OpCode)
                {
                    case "ldnull":
                        stack.Push("null"); break;
                    case "ldstr":
                        stack.Push($"string: {instr.Operand[..Math.Min(30, instr.Operand.Length)]}"); break;
                    case "ldc.i4": case "ldc.i4.s":
                    case "ldc.i4.0": case "ldc.i4.1": case "ldc.i4.2": case "ldc.i4.3":
                    case "ldc.i4.4": case "ldc.i4.5": case "ldc.i4.6": case "ldc.i4.7":
                    case "ldc.i4.8": case "ldc.i4.m1":
                        stack.Push($"int32: {instr.Operand}"); break;
                    case "ldc.i8": stack.Push($"int64: {instr.Operand}"); break;
                    case "ldc.r4": stack.Push("float32"); break;
                    case "ldc.r8": stack.Push("float64"); break;
                    case "ldarg.0": stack.Push("arg0"); break;
                    case "ldarg.1": stack.Push("arg1"); break;
                    case "ldarg.2": stack.Push("arg2"); break;
                    case "ldarg.3": stack.Push("arg3"); break;
                    case "ldloc.0": stack.Push("local0"); break;
                    case "ldloc.1": stack.Push("local1"); break;
                    case "ldloc.2": stack.Push("local2"); break;
                    case "ldloc.3": stack.Push("local3"); break;
                    case "dup":
                        if (stack.Count > 0) { var t = stack.Peek(); stack.Push(t); }
                        break;
                    case "pop":
                        if (stack.Count > 0) stack.Pop();
                        break;
                    case "ldsfld":
                        stack.Push($"field: {instr.Operand}");
                        break;
                    case "ldfld":
                        if (stack.Count > 0) stack.Pop();
                        stack.Push($"field: {instr.Operand}");
                        break;
                    case "stfld":
                        if (stack.Count > 0) stack.Pop(); 
                        if (stack.Count > 0) stack.Pop(); 
                        break;
                    case "stsfld":
                        if (stack.Count > 0) stack.Pop();
                        break;
                    case "call": case "callvirt": case "newobj":
                        for (int j = 0; j < 3 && stack.Count > 0; j++) stack.Pop();
                        stack.Push($"result: {instr.Operand[..Math.Min(40, instr.Operand.Length)]}");
                        break;
                    case "ret":
                        stack.Clear(); break;
                    case "ceq": case "cgt": case "cgt.un": case "clt": case "clt.un":
                        if (stack.Count > 0) stack.Pop();
                        if (stack.Count > 0) stack.Pop();
                        stack.Push("bool");
                        break;
                    case "add": case "sub": case "mul": case "div": case "rem":
                    case "and": case "or": case "xor": case "shl": case "shr": case "shr.un":
                        if (stack.Count > 1) { var a = stack.Pop(); stack.Pop(); stack.Push(a); }
                        break;
                    case "newarr":
                        if (stack.Count > 0) stack.Pop();
                        stack.Push($"array: {instr.Operand}");
                        break;
                    case "ldlen":
                        if (stack.Count > 0) stack.Pop();
                        stack.Push("int32 (length)");
                        break;
                    case "box":
                        if (stack.Count > 0) { stack.Pop(); stack.Push($"boxed: {instr.Operand}"); }
                        break;
                    default:
                        if (instr.StackEffect.StartsWith("push") && !instr.StackEffect.Contains("pop"))
                            stack.Push($"?({instr.OpCode})");
                        else if (instr.StackEffect == "pop" && stack.Count > 0)
                            stack.Pop();
                        break;
                }
            }
            catch {  }
        }
        return stack.Reverse().ToList();
    }

    private static List<string> FindCallers(IMethod target, PEFile peFile)
    {
        var callers = new List<string>();
        var meta = peFile.Metadata;
        int targetToken = GetToken(target.MetadataToken);
        var tokenBytes = BitConverter.GetBytes(targetToken);

        foreach (var tdh in meta.TypeDefinitions)
        {
            string typeName;
            TypeDefinition td;
            try
            {
                td = meta.GetTypeDefinition(tdh);
                var ns = meta.GetString(td.Namespace);
                var nm = meta.GetString(td.Name);
                typeName = string.IsNullOrEmpty(ns) ? nm : $"{ns}.{nm}";
            }
            catch { continue; }

            foreach (var mh in td.GetMethods())
            {
                try
                {
                    var md = meta.GetMethodDefinition(mh);
                    if (md.RelativeVirtualAddress == 0) continue;
                    var body = peFile.Reader.GetMethodBody(md.RelativeVirtualAddress);
                    var ilReader = body.GetILReader();
                    var ilBytes = ilReader.ReadBytes(ilReader.RemainingBytes);
                    if (ilBytes.AsSpan().IndexOf(tokenBytes.AsSpan()) >= 0)
                        callers.Add($"{typeName}.{meta.GetString(md.Name)}");
                }
                catch { }
            }
        }
        return callers;
    }
}
