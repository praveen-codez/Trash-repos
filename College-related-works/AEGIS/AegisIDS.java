// AEGIS-IDS : an offline, anomaly-based Network Intrusion Detection System.
//
// Pipeline:
//   1. Load network flows from a CSV (BufferedReader + split, no libraries).
//   2. Store them as FlowRecord objects, merging both directions of a flow.
//   3. Learn a "normal" baseline (mean + standard deviation) from clean traffic.
//   4. Score new traffic with a Z-Score; alert when |Z| > 3.0.

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

public class AegisIDS {

    static final String TRAINING_FILE = "training_flows.csv";  // clean, attack-free traffic
    static final String TEST_FILE     = "test_flows.csv";      // unknown traffic to scan
    static final double THRESHOLD      = 3.0;                   // alert when |Z-Score| exceeds this

    // Holds the two baseline numbers together so we can return them as one object.
    static class Baseline {
        double mean;
        double stdDev;
        Baseline(double mean, double stdDev) {
            this.mean = mean;
            this.stdDev = stdDev;
        }
    }

    public static void main(String[] args) {
        System.out.println("=== AEGIS-IDS ===\n");

        // TRAIN: learn what normal looks like.
        generateTrainingCsv();
        Map<String, FlowRecord> trainingFlows = loadFlows(TRAINING_FILE);
        Baseline baseline = calculateBaseline(trainingFlows);
        System.out.printf("%nBaseline learned -> Mean = %.4f , StdDev = %.4f%n",
                          baseline.mean, baseline.stdDev);

        // DETECT: scan unknown traffic for anomalies.
        generateTestCsv();
        Map<String, FlowRecord> testFlows = loadFlows(TEST_FILE);
        detectAnomalies(testFlows, baseline);
    }

    // Z-Score detection: Z = (X - Mean) / StdDev. Alert when the distance is too large.
    static void detectAnomalies(Map<String, FlowRecord> testFlows, Baseline baseline) {
        System.out.println("\n--- Scanning test traffic (alert when |Z| > " + THRESHOLD + ") ---\n");

        if (baseline.stdDev == 0.0) {   // guard against divide-by-zero
            System.out.println("[WARN] Standard deviation is 0 — cannot compute Z-scores.");
            return;
        }

        int anomalyCount = 0;
        for (FlowRecord flow : testFlows.values()) {
            double z = (flow.totalPackets - baseline.mean) / baseline.stdDev;

            if (Math.abs(z) > THRESHOLD) {   // abs(): abnormally high OR low both count
                anomalyCount++;
                System.out.println("!!! ANOMALY DETECTED: Potential DoS Attack");
                System.out.println("    Flow    : " + flow);
                System.out.printf ("    Z-Score : %.2f%n%n", z);
            } else {
                System.out.printf("[OK] Normal | packets=%-4d | Z=%6.2f%n",
                                  flow.totalPackets, z);
            }
        }

        System.out.println("\n--- Scan complete: " + anomalyCount
                         + " anomaly(ies) in " + testFlows.size() + " flows ---");
    }

    // Learns the mean and standard deviation of totalPackets from clean flows.
    static Baseline calculateBaseline(Map<String, FlowRecord> trainingFlows) {
        int count = trainingFlows.size();
        if (count == 0) {
            return new Baseline(0.0, 0.0);
        }

        // Mean = sum / count. Cast to double so we keep the decimal part.
        int sum = 0;
        for (FlowRecord flow : trainingFlows.values()) {
            sum += flow.totalPackets;
        }
        double mean = (double) sum / count;

        // Std dev = sqrt(average squared distance from the mean).
        double sumSquaredDiffs = 0.0;
        for (FlowRecord flow : trainingFlows.values()) {
            double diff = flow.totalPackets - mean;
            sumSquaredDiffs += diff * diff;
        }
        double stdDev = Math.sqrt(sumSquaredDiffs / count);

        return new Baseline(mean, stdDev);
    }

    // Reads a CSV into a HashMap of flows, merging reverse directions via the canonical key.
    static Map<String, FlowRecord> loadFlows(String fileName) {
        Map<String, FlowRecord> flowTable = new HashMap<>();

        try (BufferedReader reader = new BufferedReader(new FileReader(fileName))) {
            String  line;
            boolean isHeader = true;

            while ((line = reader.readLine()) != null) {
                if (isHeader) { isHeader = false; continue; }   // skip column names
                if (line.trim().isEmpty()) { continue; }

                String[] columns = line.split(",");
                if (columns.length != 6) {
                    System.out.println("[SKIP] Bad row: " + line);
                    continue;
                }

                FlowRecord record = new FlowRecord(
                    columns[0],                       // sourceIp
                    columns[1],                       // destIp
                    Integer.parseInt(columns[2]),     // sourcePort
                    Integer.parseInt(columns[3]),     // destPort
                    columns[4],                       // protocol
                    Integer.parseInt(columns[5]));    // totalPackets

                String key = record.getCanonicalKey();
                if (flowTable.containsKey(key)) {
                    flowTable.get(key).addPackets(record.totalPackets);  // merge reverse direction
                } else {
                    flowTable.put(key, record);
                }
            }
            System.out.println("[INFO] '" + fileName + "' -> " + flowTable.size() + " unique flows");

        } catch (IOException e) {
            System.out.println("[ERROR] Could not read file: " + e.getMessage());
        } catch (NumberFormatException e) {
            System.out.println("[ERROR] Non-numeric value in a number column: " + e.getMessage());
        }

        return flowTable;
    }

    // Clean training data: all normal (5..14 packets). Row 2 is the reverse of row 1 (merges to 14).
    static void generateTrainingCsv() {
        String csv =
            "SourceIP,DestIP,SourcePort,DestPort,Protocol,TotalPackets\n" +
            "192.168.1.10,10.0.0.5,52344,80,TCP,8\n"   +
            "10.0.0.5,192.168.1.10,80,52344,TCP,6\n"   +
            "192.168.1.11,10.0.0.5,52990,443,TCP,12\n" +
            "192.168.1.10,10.0.0.7,49001,53,UDP,5\n"   +
            "192.168.1.12,10.0.0.5,50122,80,TCP,9\n"   +
            "192.168.1.13,10.0.0.9,51999,22,TCP,7\n"   +
            "192.168.1.14,10.0.0.5,53001,80,TCP,10\n";
        writeFile(TRAINING_FILE, csv);
    }

    // Test data: normal flows plus two attacks (5000 and 800 packets) that must be flagged.
    static void generateTestCsv() {
        String csv =
            "SourceIP,DestIP,SourcePort,DestPort,Protocol,TotalPackets\n" +
            "192.168.1.20,10.0.0.5,55000,80,TCP,11\n"   +
            "192.168.1.21,10.0.0.8,55234,443,TCP,6\n"   +
            "192.168.1.22,10.0.0.5,55999,53,UDP,9\n"    +
            "192.168.1.66,10.0.0.5,60000,80,TCP,5000\n" +   // DoS flood
            "192.168.1.99,10.0.0.5,61000,80,TCP,800\n";     // flood / exfiltration
        writeFile(TEST_FILE, csv);
    }

    static void writeFile(String fileName, String content) {
        try (FileWriter writer = new FileWriter(fileName)) {
            writer.write(content);
            System.out.println("[OK] Wrote: " + fileName);
        } catch (IOException e) {
            System.out.println("[ERROR] Could not write " + fileName + ": " + e.getMessage());
        }
    }
}
