namespace EthernetIPSharp.Cip;

/// <summary>
/// Central CIP message dispatch interface.
/// Both adapter (server) and scanner (client) implementations consume this.
/// An adapter provides a dispatch that handles incoming requests from a PLC.
/// A scanner could provide a dispatch that handles incoming responses or unsolicited messages.
/// </summary>
public interface ICipDispatch
{
    /// <summary>
    /// Dispatch a CIP service request and return a response.
    /// </summary>
    /// <param name="serviceCode">CIP service code (e.g. 0x0E = GetAttributeSingle)</param>
    /// <param name="path">Parsed EPATH — class, instance, attribute, connection point</param>
    /// <param name="data">Service-specific request data</param>
    /// <returns>CIP service response</returns>
    CipServiceResponse Dispatch(byte serviceCode, CipPath path, ReadOnlyMemory<byte> data);
}
