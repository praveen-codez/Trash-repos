// AEGIS-IDS : represents one network flow (a summarized conversation between two computers).

public class FlowRecord {

    String sourceIp;
    String destIp;
    int    sourcePort;
    int    destPort;
    String protocol;
    int    totalPackets;

    public FlowRecord(String sourceIp, String destIp, int sourcePort,
                      int destPort, String protocol, int totalPackets) {
        this.sourceIp     = sourceIp;
        this.destIp       = destIp;
        this.sourcePort   = sourcePort;
        this.destPort     = destPort;
        this.protocol     = protocol;
        this.totalPackets = totalPackets;
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
    public void addPackets(int morePackets) {
        this.totalPackets += morePackets;
    }

    @Override
    public String toString() {
        return sourceIp + ":" + sourcePort + "  <->  " + destIp + ":" + destPort
             + "   | " + protocol + " | TotalPackets = " + totalPackets;
    }
}
