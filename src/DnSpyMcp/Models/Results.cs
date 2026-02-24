namespace DnSpyMcp.Models;

public record TypeInfo(
    string FullName,
    string Namespace,
    string Kind,
    bool IsPublic,
    bool IsAbstract,
    bool IsSealed,
    List<string> Interfaces
);

public record MethodSummary(
    string Name,
    string FullName,
    string ReturnType,
    bool IsPublic,
    bool IsStatic,
    bool IsAbstract,
    bool IsVirtual,
    List<string> Parameters
);

public record FieldSummary(
    string Name,
    string Type,
    bool IsPublic,
    bool IsStatic,
    bool IsReadOnly
);

public record PropertySummary(
    string Name,
    string Type,
    bool CanRead,
    bool CanWrite,
    bool IsPublic,
    bool IsStatic
);

public record MemberSearchResult(
    string MemberKind,
    string FullName,
    string? Signature,
    string? DeclaringType
);

public record StringSearchResult(
    string Value,
    string FoundInType,
    string FoundInMethod
);

public record ResourceInfo(
    string Name,
    string ResourceType,
    long Offset
);

public record PEInfo(
    string Architecture,
    bool Is64Bit,
    bool IsManaged,
    string TargetFramework,
    string AssemblyName,
    string AssemblyVersion,
    bool IsSigned,
    string RuntimeVersion,
    List<string> Sections,
    Dictionary<string, string> CustomAttributes
);

public record MetadataTokenResult(
    string TokenHex,
    string TableName,
    int RowNumber,
    string? FullName,
    string? Details
);

public class TypeDetailInfo
{
    public string? FullName { get; init; }
    public string? Namespace { get; init; }
    public string? BaseType { get; init; }
    public string? Kind { get; init; }
    public bool IsAbstract { get; init; }
    public bool IsSealed { get; init; }
    public bool IsInterface { get; init; }
    public bool IsPublic { get; init; }
    public List<FieldSummary> Fields { get; init; } = [];
    public List<MethodSummary> Methods { get; init; } = [];
    public List<PropertySummary> Properties { get; init; } = [];
    public List<string> Interfaces { get; init; } = [];
    public string? DecompiledSource { get; init; }
}

public class MethodDetailInfo
{
    public string? Name { get; init; }
    public string? FullName { get; init; }
    public string? ReturnType { get; init; }
    public bool IsPublic { get; init; }
    public bool IsStatic { get; init; }
    public bool IsAbstract { get; init; }
    public bool IsVirtual { get; init; }
    public List<Dictionary<string, object?>> Parameters { get; init; } = [];
    public string? DeclaringType { get; init; }
    public string? DecompiledSource { get; init; }
    public string? ILCode { get; init; }
}

public record AntiDebugFinding(
    string Category,
    string Technique,
    string Location,
    string Detail,
    string Severity
);

public record AntiTamperFinding(
    string Category,
    string Technique,
    string Evidence,
    string Location,
    string Confidence
);

public class ProtectionReport
{
    public string AssemblyPath { get; init; } = "";
    public string AssemblyName { get; init; } = "";
    public int RiskScore { get; init; }
    public List<string> Summary { get; init; } = [];
    public List<AntiDebugFinding> AntiDebugFindings { get; init; } = [];
    public List<AntiTamperFinding> AntiTamperFindings { get; init; } = [];
    public List<string> RecommendedBypasses { get; init; } = [];
    public DateTime AnalysedAt { get; init; }
}

public record ILInstruction(int Offset, string OpCode, string Operand, string StackEffect);

public class BreakpointContext
{
    public string Id { get; init; } = "";
    public string AssemblyPath { get; init; } = "";
    public string TypeName { get; init; } = "";
    public string MethodName { get; init; } = "";
    public int? ILOffset { get; init; }
    public string MethodSignature { get; init; } = "";
    public int LocalCount { get; init; }
    public int MaxStack { get; init; }
    public ILInstruction? TargetInstruction { get; init; }
    public List<ILInstruction> SurroundingIL { get; init; } = [];
    public List<string> InferredStackTypes { get; init; } = [];
    public string? DecompiledSource { get; init; }
    public List<string> Callers { get; init; } = [];
    public DateTime CreatedAt { get; init; }
}
