namespace AntiExfiltration.Core.Common;

/// <summary>
/// Specifies the action that should be taken against an outbound flow.
/// </summary>
public enum Decision
{
    Allow,
    Block,
    Obfuscate,
    Alert
}
