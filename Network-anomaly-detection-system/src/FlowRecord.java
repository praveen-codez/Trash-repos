// AEGIS-IDS : represents one network flow (a summarized conversation between two computers).

public class FlowRecord {

    String sourceIp;
    String destIp;
    int    sourcePort;
    int    destPort;
    String protocol;
    int    totalPackets;
    int    totalBytes;
    int    durationMs;

    public FlowRecord(String sourceIp, String destIp, int sourcePort,
                      int destPort, String protocol, int totalPackets,
                      int totalBytes, int durationMs) {
        this.sourceIp     = sourceIp;
        this.destIp       = destIp;
        this.sourcePort   = sourcePort;
        this.destPort     = destPort;
        this.protocol     = protocol;
        this.totalPackets = totalPackets;
        this.totalBytes   = totalBytes;
        this.durationMs   = durationMs;
    }

    // Builds a direction-independent key so A->B and B->A map to the same flow.
    // Each side becomes "ip:port"; we sort the two sides so order never matters.
    public String getCanonicalKey() {
        String endpointA = sourceIp + ":" + sourcePort;
        String endpointB = destIp   + ":" + destPort;

        String low, high;
        if (endpointA.compareTo(endpointB) <= 0) {
            low = endpointA; high = endpointB;
        } else {
            low = endpointB; high = endpointA;
        }
        return low + "<->" + high + " [" + protocol + "]";
    }

    // Used when the reverse direction of a flow is found, to combine the counts.
    // Duration takes the wider window rather than the sum: the two directions
    // overlap in time, so adding them would overstate how long the flow lasted.
    public void addFlow(int morePackets, int moreBytes, int otherDurationMs) {
        this.totalPackets += morePackets;
        this.totalBytes   += moreBytes;
        this.durationMs    = Math.max(this.durationMs, otherDurationMs);
    }

    public double packetsPerSec() {
        if (durationMs <= 0) return totalPackets;
        return totalPackets / (durationMs / 1000.0);
    }

    public double avgPacketSize() {
        if (totalPackets <= 0) return 0.0;
        return (double) totalBytes / totalPackets;
    }

    // Distinct endpoint pair without the port, used to group activity per host.
    public String getSourceHost() {
        return sourceIp;
    }

    @Override
    public String toString() {
        return sourceIp + ":" + sourcePort + "  <->  " + destIp + ":" + destPort
             + "   | " + protocol + " | TotalPackets = " + totalPackets;
    }
}
