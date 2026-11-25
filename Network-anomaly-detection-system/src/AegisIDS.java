// AEGIS-IDS : an offline, anomaly-based Network Intrusion Detection System.
//
// Pipeline:
//   1. Load network flows from a CSV (BufferedReader + split, no libraries).
//   2. Store them as FlowRecord objects, merging both directions of a flow.
//   3. Learn a "normal" baseline (mean + standard deviation) for FOUR features.
//   4. Score new traffic with a per-feature Z-Score, then classify what kind of
//      attack the deviation pattern looks like and how severe it is.
//
// Detection is deliberately two-track: a statistical track (per-feature Z-Scores,
// which catch volume anomalies) and a rule track (cross-flow context, which catches
// patterns no single flow reveals -- a port scan looks harmless one flow at a time).

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Random;
import java.util.Set;
import java.util.TreeSet;

// Web Server Imports
import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpExchange;
import java.net.InetSocketAddress;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Paths;

public class AegisIDS {

    static final String TRAINING_FILE = "data/training_flows.csv";  // clean, attack-free traffic
    static final String TEST_FILE     = "data/test_flows.csv";      // unknown traffic to scan
    static final double THRESHOLD     = 3.0;                        // alert when |Z-Score| exceeds this

    // A port-scan is a fan-out pattern: one source touching many destination ports.
    static final int    FANOUT_SCAN   = 8;

    // Mean and standard deviation of one feature across the clean training set.
    static class FeatureStats {
        double mean;
        double stdDev;
        FeatureStats(double mean, double stdDev) {
            this.mean   = mean;
            this.stdDev = stdDev;
        }
        // Distance from normal, in standard deviations. Zero sigma means the feature
        // never varied in training, so it carries no information -- score it flat.
        double z(double x) {
            if (stdDev == 0.0) return 0.0;
            return (x - mean) / stdDev;
        }
        double cutoff() {
            return mean + THRESHOLD * stdDev;
        }
    }

    // Holds one FeatureStats per scored feature.
    static class Baseline {
        FeatureStats packets;
        FeatureStats bytes;
        FeatureStats pps;
        FeatureStats avgPktSize;
    }

    // The engine's conclusion about a single flow.
    static class Verdict {
        FlowRecord flow;
        double zPackets, zBytes, zPps, zAvgSize;
        double composite;        // largest absolute z across the four features
        String severity;         // CRITICAL / HIGH / MEDIUM / LOW / NORMAL
        String attackType;       // null when nothing fired
        String mitre;            // MITRE ATT&CK technique id, null when unclassified
        double confidence;       // percent, from the two-tailed normal tail probability

        boolean isAnomaly() {
            return attackType != null;
        }
    }

    public static void main(String[] args) {
        banner();

        // TRAIN: learn what normal looks like, across every feature.
        System.out.println("[*] PHASE 1 - BASELINE TRAINING");
        generateTrainingCsv();
        Map<String, FlowRecord> trainingFlows = loadFlows(TRAINING_FILE);
        Baseline baseline = calculateBaseline(trainingFlows);
        printBaseline(baseline);

        // DETECT: scan unknown traffic, classify whatever deviates.
        System.out.println("\n[*] PHASE 2 - TRAFFIC SCAN");
        generateTestCsv();
        Map<String, FlowRecord> testFlows = loadFlows(TEST_FILE);
        List<Verdict> verdicts = analyse(testFlows, baseline);
        printVerdicts(verdicts);
        printSummary(verdicts);
        printTopOffenders(verdicts);

        // START WEB SERVER
        try {
            startServer(baseline);
        } catch (Exception e) {
            System.out.println("[ERROR] Failed to start web server: " + e.getMessage());
        }
    }

    static void banner() {
        System.out.println("===============================================================");
        System.out.println("   AEGIS-IDS  -  Anomaly-Based Network Intrusion Detection");
        System.out.println("   Multi-Feature Z-Score Engine  -  Core Java, no libraries");
        System.out.println("===============================================================\n");
    }

    // ---------------------------------------------------------------------------
    // Baseline learning
    // ---------------------------------------------------------------------------

    // Learns mean and standard deviation for each of the four scored features.
    static Baseline calculateBaseline(Map<String, FlowRecord> trainingFlows) {
        Baseline b = new Baseline();

        List<Double> packets    = new ArrayList<>();
        List<Double> bytes      = new ArrayList<>();
        List<Double> pps        = new ArrayList<>();
        List<Double> avgPktSize = new ArrayList<>();

        for (FlowRecord f : trainingFlows.values()) {
            packets.add((double) f.totalPackets);
            bytes.add((double) f.totalBytes);
            pps.add(f.packetsPerSec());
            avgPktSize.add(f.avgPacketSize());
        }

        b.packets    = statsOf(packets);
        b.bytes      = statsOf(bytes);
        b.pps        = statsOf(pps);
        b.avgPktSize = statsOf(avgPktSize);
        return b;
    }

    // Mean = sum / count. Std dev = sqrt(average squared distance from the mean).
    // Population form (divide by n), matching the project's documented method.
    static FeatureStats statsOf(List<Double> values) {
        int count = values.size();
        if (count == 0) return new FeatureStats(0.0, 0.0);

        double sum = 0.0;
        for (double v : values) sum += v;
        double mean = sum / count;

        double sumSquaredDiffs = 0.0;
        for (double v : values) {
            double diff = v - mean;
            sumSquaredDiffs += diff * diff;
        }
        double stdDev = Math.sqrt(sumSquaredDiffs / count);

        return new FeatureStats(mean, stdDev);
    }

    static void printBaseline(Baseline b) {
        System.out.println();
        System.out.printf(Locale.US, "    %-20s %12s %12s %14s%n",
                          "Feature", "Mean", "StdDev", "Cut-off(+3s)");
        System.out.println("    " + repeat('-', 60));
        baselineRow("Total packets",   b.packets);
        baselineRow("Total bytes",     b.bytes);
        baselineRow("Packets / sec",   b.pps);
        baselineRow("Avg packet size", b.avgPktSize);
    }

    static void baselineRow(String label, FeatureStats s) {
        System.out.printf(Locale.US, "    %-20s %12.2f %12.2f %14.2f%n",
                          label, s.mean, s.stdDev, s.cutoff());
    }

    // ---------------------------------------------------------------------------
    // Analysis : scoring, classification, severity
    // ---------------------------------------------------------------------------

    // Scores every flow, then classifies it using both its own z-scores and
    // cross-flow context (how many distinct ports its source touched).
    static List<Verdict> analyse(Map<String, FlowRecord> testFlows, Baseline baseline) {
        // Pre-pass: fan-out per source host. A port scan is invisible one flow at a
        // time -- it only shows up once you count how many ports a host probed.
        Map<String, Set<Integer>> portsPerSource = new HashMap<>();
        for (FlowRecord f : testFlows.values()) {
            portsPerSource
                .computeIfAbsent(f.getSourceHost(), k -> new HashSet<>())
                .add(f.destPort);
        }

        List<Verdict> verdicts = new ArrayList<>();
        for (FlowRecord f : testFlows.values()) {
            Verdict v = new Verdict();
            v.flow = f;

            v.zPackets = baseline.packets.z(f.totalPackets);
            v.zBytes   = baseline.bytes.z(f.totalBytes);
            v.zPps     = baseline.pps.z(f.packetsPerSec());
            v.zAvgSize = baseline.avgPktSize.z(f.avgPacketSize());

            v.composite = Math.max(
                Math.max(Math.abs(v.zPackets), Math.abs(v.zBytes)),
                Math.max(Math.abs(v.zPps),     Math.abs(v.zAvgSize)));

            int fanout = portsPerSource.get(f.getSourceHost()).size();
            classify(v, fanout);
            v.severity   = severityOf(v);
            v.confidence = confidenceOf(v.composite);

            verdicts.add(v);
        }

        // Loudest first, so a reviewer sees the worst finding immediately.
        verdicts.sort(Comparator.comparingDouble((Verdict v) -> -v.composite));
        return verdicts;
    }

    // Decides what KIND of attack the deviation pattern resembles. Order matters:
    // the fan-out test runs first because a scan's per-flow z-scores are ambiguous.
    static void classify(Verdict v, int fanout) {
        FlowRecord f = v.flow;

        // Port scan: one host probing many ports, a few packets each.
        if (fanout >= FANOUT_SCAN && f.totalPackets <= 5) {
            v.attackType = "Port Scan";
            v.mitre      = "T1046";
            return;
        }

        // DoS flood: packet volume far above normal, aimed at a single service.
        if (v.zPackets > THRESHOLD && fanout <= 2) {
            v.attackType = "DoS Flood";
            v.mitre      = "T1498";
            return;
        }

        // Exfiltration: ordinary packet COUNT, extraordinary packet SIZE. The
        // volume hides inside the normal band; only the byte total gives it away.
        if (v.zBytes > THRESHOLD && v.zAvgSize > THRESHOLD && v.zPackets <= THRESHOLD) {
            v.attackType = "Data Exfiltration";
            v.mitre      = "T1041";
            return;
        }

        // Low-and-slow probe: trickled out over a long window to stay under the
        // volume thresholds. This one HAS to be a rule rather than a Z-Score: the
        // packets-per-second standard deviation (~6) is wider than its mean (~8.5),
        // so no positive rate can ever sit 3 sigma below normal. The statistical
        // track is structurally blind here, and the rule track covers the gap.
        if (f.packetsPerSec() < 1.0 && f.durationMs > 30000) {
            v.attackType = "Low-and-Slow Probe";
            v.mitre      = "T1095";
            return;
        }

        // Something deviated, but it matches no known pattern. Still worth surfacing.
        if (v.composite > THRESHOLD) {
            v.attackType = "Unclassified Anomaly";
            v.mitre      = null;
        }
    }

    // Statistical magnitude sets the severity, but a rule hit floors it at MEDIUM:
    // a confirmed port scan matters even when no single flow looks extreme.
    static String severityOf(Verdict v) {
        String s;
        if      (v.composite >= 100) s = "CRITICAL";
        else if (v.composite >=  20) s = "HIGH";
        else if (v.composite >=   3) s = "MEDIUM";
        else if (v.composite >=   2) s = "LOW";
        else                         s = "NORMAL";

        if (v.isAnomaly() && (s.equals("NORMAL") || s.equals("LOW"))) {
            s = "MEDIUM";
        }
        return s;
    }

    static int riskWeight(String severity) {
        switch (severity) {
            case "CRITICAL": return 100;
            case "HIGH":     return 60;
            case "MEDIUM":   return 30;
            case "LOW":      return 10;
            default:         return 0;
        }
    }

    // ---------------------------------------------------------------------------
    // Statistics : how surprising is this z-score?
    // ---------------------------------------------------------------------------

    // Two-tailed probability that a normal variable lands at least |z| from the
    // mean, expressed as a confidence percentage. Turns "z = 4.1" into "99.9959%",
    // which is the number that actually answers "how sure are you?".
    static double confidenceOf(double z) {
        double p = erfc(Math.abs(z) / Math.sqrt(2.0));   // two-tailed p-value
        double conf = (1.0 - p) * 100.0;
        if (conf < 0.0)      conf = 0.0;
        if (conf > 99.9999)  conf = 99.9999;             // cap, p underflows past z~7
        return conf;
    }

    // Complementary error function, Numerical Recipes rational approximation.
    // Accurate to ~1.2e-7 -- plenty, and it keeps the zero-dependency rule.
    static double erfc(double x) {
        double z = Math.abs(x);
        double t = 1.0 / (1.0 + 0.5 * z);
        double ans = t * Math.exp(-z * z - 1.26551223 + t * (1.00002368
                   + t * (0.37409196 + t * (0.09678418 + t * (-0.18628806
                   + t * (0.27886807 + t * (-1.13520398 + t * (1.48851587
                   + t * (-0.82215223 + t * 0.17087277)))))))));
        return x >= 0.0 ? ans : 2.0 - ans;
    }

    // ---------------------------------------------------------------------------
    // Console reporting
    // ---------------------------------------------------------------------------

    static void printVerdicts(List<Verdict> verdicts) {
        System.out.println("\n--- FLOW VERDICTS (alert when |Z| > " + THRESHOLD
                         + " on any feature, or a rule fires) ---\n");

        for (Verdict v : verdicts) {
            if (!v.isAnomaly()) {
                System.out.printf(Locale.US,
                    "[OK]   NORMAL   | pkts=%-5d bytes=%-8d pps=%-7.1f | Zmax=%7.2f%n",
                    v.flow.totalPackets, v.flow.totalBytes,
                    v.flow.packetsPerSec(), v.composite);
            } else {
                String tag = v.mitre == null ? "" : " [" + v.mitre + "]";
                System.out.printf(Locale.US,
                    "%n[!!]   %-8s | %-20s%-8s | Zmax=%9.2f | conf=%.4f%%%n",
                    v.severity, v.attackType, tag, v.composite, v.confidence);
                System.out.println("       " + v.flow);
                System.out.printf(Locale.US,
                    "       z: pkts=%+.1f  bytes=%+.1f  pps=%+.1f  size=%+.1f%n%n",
                    v.zPackets, v.zBytes, v.zPps, v.zAvgSize);
            }
        }
    }

    static void printSummary(List<Verdict> verdicts) {
        int total = verdicts.size();
        int alerts = 0, critical = 0, high = 0, medium = 0, low = 0;
        double peakConf = 0.0;
        Map<String, Integer> byType = new LinkedHashMap<>();

        for (Verdict v : verdicts) {
            if (v.isAnomaly()) {
                alerts++;
                byType.merge(v.attackType, 1, Integer::sum);
                peakConf = Math.max(peakConf, v.confidence);
            }
            switch (v.severity) {
                case "CRITICAL": critical++; break;
                case "HIGH":     high++;     break;
                case "MEDIUM":   medium++;   break;
                case "LOW":      low++;      break;
            }
        }

        System.out.println("--- SCAN SUMMARY " + repeat('-', 45));
        System.out.printf(Locale.US, "  Flows scanned   : %d%n", total);
        System.out.printf(Locale.US, "  Alerts raised   : %d%n", alerts);
        System.out.printf(Locale.US, "  By severity     : CRITICAL=%d  HIGH=%d  MEDIUM=%d  LOW=%d%n",
                          critical, high, medium, low);

        StringBuilder types = new StringBuilder();
        for (Map.Entry<String, Integer> e : byType.entrySet()) {
            if (types.length() > 0) types.append("  ");
            types.append(e.getKey()).append("=").append(e.getValue());
        }
        System.out.println("  By attack type  : " + (types.length() == 0 ? "none" : types));
        System.out.printf(Locale.US, "  Benign flows    : %d%n", total - alerts);
        System.out.printf(Locale.US, "  Peak confidence : %.4f%%%n", peakConf);
    }

    static void printTopOffenders(List<Verdict> verdicts) {
        List<String[]> rows = topOffenders(verdicts);
        if (rows.isEmpty()) return;

        System.out.println("\n--- TOP OFFENDING HOSTS " + repeat('-', 38));
        int rank = 1;
        for (String[] r : rows) {
            System.out.printf(Locale.US, "  %d. %-16s risk=%-5s flows=%-3s %s%n",
                              rank++, r[0], r[1], r[2], r[3]);
        }
        System.out.println();
    }

    // Aggregates risk per source host. A port scan is 12 separate flows but one
    // attacker -- this is the view that makes that obvious.
    static List<String[]> topOffenders(List<Verdict> verdicts) {
        Map<String, Integer>      risk  = new HashMap<>();
        Map<String, Integer>      count = new HashMap<>();
        Map<String, Set<String>>  types = new HashMap<>();

        for (Verdict v : verdicts) {
            if (!v.isAnomaly()) continue;
            String host = v.flow.getSourceHost();
            risk.merge(host, riskWeight(v.severity), Integer::sum);
            count.merge(host, 1, Integer::sum);
            types.computeIfAbsent(host, k -> new TreeSet<>()).add(v.attackType);
        }

        List<String> hosts = new ArrayList<>(risk.keySet());
        hosts.sort((a, b) -> risk.get(b) - risk.get(a));

        List<String[]> rows = new ArrayList<>();
        for (String h : hosts) {
            rows.add(new String[] {
                h,
                String.valueOf(risk.get(h)),
                String.valueOf(count.get(h)),
                String.join(", ", types.get(h))
            });
        }
        return rows;
    }

    static String repeat(char c, int n) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < n; i++) sb.append(c);
        return sb.toString();
    }

    // ---------------------------------------------------------------------------
    // Web server
    // ---------------------------------------------------------------------------

    static void startServer(Baseline baseline) throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress(8080), 0);

        // Serve frontend
        server.createContext("/", new HttpHandler() {
            @Override
            public void handle(HttpExchange exchange) throws IOException {
                if (!exchange.getRequestURI().getPath().equals("/")) {
                    exchange.sendResponseHeaders(404, -1);
                    return;
                }
                byte[] response = Files.readAllBytes(Paths.get("index.html"));
                exchange.getResponseHeaders().set("Content-Type", "text/html; charset=utf-8");
                exchange.sendResponseHeaders(200, response.length);
                try (OutputStream os = exchange.getResponseBody()) {
                    os.write(response);
                }
            }
        });

        // API Endpoint
        server.createContext("/api/scan", new HttpHandler() {
            @Override
            public void handle(HttpExchange exchange) throws IOException {
                exchange.getResponseHeaders().set("Content-Type", "application/json");

                // Re-run the scan for the API
                generateTestCsv();
                Map<String, FlowRecord> testFlows = loadFlows(TEST_FILE);
                List<Verdict> verdicts = analyse(testFlows, baseline);

                byte[] response = buildJson(baseline, verdicts).getBytes("UTF-8");
                exchange.sendResponseHeaders(200, response.length);
                try (OutputStream os = exchange.getResponseBody()) {
                    os.write(response);
                }
            }
        });

        server.setExecutor(null);
        server.start();
        System.out.println("============================================");
        System.out.println("[WEB] Server started on port 8080!");
        System.out.println("      Open http://localhost:8080/ in your browser.");
        System.out.println("============================================\n");
    }

    // Hand-built JSON -- the project deliberately uses no serialisation library.
    static String buildJson(Baseline baseline, List<Verdict> verdicts) {
        StringBuilder json = new StringBuilder();
        json.append("{");

        // --- baseline, one block per feature ---
        json.append("\"baseline\":{")
            .append("\"packets\":").append(featureJson(baseline.packets)).append(",")
            .append("\"bytes\":").append(featureJson(baseline.bytes)).append(",")
            .append("\"pps\":").append(featureJson(baseline.pps)).append(",")
            .append("\"avgPktSize\":").append(featureJson(baseline.avgPktSize))
            .append("},");

        // --- summary ---
        int alerts = 0, critical = 0, high = 0, medium = 0, low = 0;
        double peakConf = 0.0;
        Map<String, Integer> byType = new LinkedHashMap<>();
        for (Verdict v : verdicts) {
            if (v.isAnomaly()) {
                alerts++;
                byType.merge(v.attackType, 1, Integer::sum);
                peakConf = Math.max(peakConf, v.confidence);
            }
            switch (v.severity) {
                case "CRITICAL": critical++; break;
                case "HIGH":     high++;     break;
                case "MEDIUM":   medium++;   break;
                case "LOW":      low++;      break;
            }
        }

        json.append("\"summary\":{")
            .append("\"totalFlows\":").append(verdicts.size()).append(",")
            .append("\"alerts\":").append(alerts).append(",")
            .append("\"benign\":").append(verdicts.size() - alerts).append(",")
            .append("\"critical\":").append(critical).append(",")
            .append("\"high\":").append(high).append(",")
            .append("\"medium\":").append(medium).append(",")
            .append("\"low\":").append(low).append(",")
            .append("\"peakConfidence\":").append(num(peakConf)).append(",")
            .append("\"attackTypes\":[");
        boolean firstType = true;
        for (Map.Entry<String, Integer> e : byType.entrySet()) {
            if (!firstType) json.append(",");
            firstType = false;
            json.append("{\"type\":\"").append(esc(e.getKey())).append("\",")
                .append("\"count\":").append(e.getValue()).append("}");
        }
        json.append("]},");

        // --- top offenders ---
        json.append("\"topOffenders\":[");
        boolean firstHost = true;
        for (String[] r : topOffenders(verdicts)) {
            if (!firstHost) json.append(",");
            firstHost = false;
            json.append("{\"host\":\"").append(esc(r[0])).append("\",")
                .append("\"risk\":").append(r[1]).append(",")
                .append("\"flows\":").append(r[2]).append(",")
                .append("\"types\":\"").append(esc(r[3])).append("\"}");
        }
        json.append("],");

        // --- per-flow results ---
        json.append("\"results\":[");
        boolean first = true;
        for (Verdict v : verdicts) {
            if (!first) json.append(",");
            first = false;
            FlowRecord f = v.flow;
            json.append("{")
                .append("\"isAnomaly\":").append(v.isAnomaly()).append(",")
                .append("\"flow\":\"").append(esc(f.toString())).append("\",")
                .append("\"sourceIp\":\"").append(esc(f.sourceIp)).append("\",")
                .append("\"destIp\":\"").append(esc(f.destIp)).append("\",")
                .append("\"destPort\":").append(f.destPort).append(",")
                .append("\"protocol\":\"").append(esc(f.protocol)).append("\",")
                .append("\"packets\":").append(f.totalPackets).append(",")
                .append("\"bytes\":").append(f.totalBytes).append(",")
                .append("\"durationMs\":").append(f.durationMs).append(",")
                .append("\"pps\":").append(num(f.packetsPerSec())).append(",")
                .append("\"avgPktSize\":").append(num(f.avgPacketSize())).append(",")
                .append("\"zPackets\":").append(num(v.zPackets)).append(",")
                .append("\"zBytes\":").append(num(v.zBytes)).append(",")
                .append("\"zPps\":").append(num(v.zPps)).append(",")
                .append("\"zAvgSize\":").append(num(v.zAvgSize)).append(",")
                .append("\"zScore\":").append(num(v.zPackets)).append(",")
                .append("\"composite\":").append(num(v.composite)).append(",")
                .append("\"severity\":\"").append(v.severity).append("\",")
                .append("\"attackType\":").append(v.attackType == null
                        ? "null" : "\"" + esc(v.attackType) + "\"").append(",")
                .append("\"mitre\":").append(v.mitre == null
                        ? "null" : "\"" + v.mitre + "\"").append(",")
                .append("\"confidence\":").append(num(v.confidence))
                .append("}");
        }
        json.append("]}");

        return json.toString();
    }

    static String featureJson(FeatureStats s) {
        return "{\"mean\":" + num(s.mean)
             + ",\"stdDev\":" + num(s.stdDev)
             + ",\"cutoff\":" + num(s.cutoff()) + "}";
    }

    // Locale.US matters: a comma decimal separator would produce invalid JSON.
    // NaN and Infinity are not valid JSON either, so they collapse to 0.
    static String num(double d) {
        if (Double.isNaN(d) || Double.isInfinite(d)) return "0";
        return String.format(Locale.US, "%.4f", d);
    }

    static String esc(String s) {
        return s.replace("\\", "\\\\").replace("\"", "\\\"");
    }

    // ---------------------------------------------------------------------------
    // CSV loading
    // ---------------------------------------------------------------------------

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
                if (columns.length != 8) {
                    System.out.println("[SKIP] Bad row: " + line);
                    continue;
                }

                FlowRecord record = new FlowRecord(
                    columns[0],                       // sourceIp
                    columns[1],                       // destIp
                    Integer.parseInt(columns[2]),     // sourcePort
                    Integer.parseInt(columns[3]),     // destPort
                    columns[4],                       // protocol
                    Integer.parseInt(columns[5]),     // totalPackets
                    Integer.parseInt(columns[6]),     // totalBytes
                    Integer.parseInt(columns[7]));    // durationMs

                String key = record.getCanonicalKey();
                if (flowTable.containsKey(key)) {
                    flowTable.get(key).addFlow(record.totalPackets,
                                               record.totalBytes,
                                               record.durationMs);   // merge reverse direction
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

    // ---------------------------------------------------------------------------
    // Traffic generation
    // ---------------------------------------------------------------------------

    static final String CSV_HEADER =
        "SourceIP,DestIP,SourcePort,DestPort,Protocol,TotalPackets,TotalBytes,DurationMs\n";

    static void row(StringBuilder csv, String src, String dst, int srcPort, int dstPort,
                    String proto, int packets, int bytes, int durationMs) {
        csv.append(String.format(Locale.US, "%s,%s,%d,%d,%s,%d,%d,%d%n",
                   src, dst, srcPort, dstPort, proto, packets, bytes, durationMs));
    }

    // Clean training data: normal flows generated with a fixed seed so the baseline is stable.
    static void generateTrainingCsv() {
        StringBuilder csv = new StringBuilder(CSV_HEADER);
        Random rand = new Random(42); // fixed seed

        for (int i = 0; i < 50; i++) {
            String src     = "192.168.1." + (10 + rand.nextInt(50));
            String dst     = "10.0.0."    + (2 + rand.nextInt(8));
            int    srcPort = 50000 + rand.nextInt(10000);
            int    dstPort = rand.nextBoolean() ? 80 : 443;
            String proto   = rand.nextBoolean() ? "TCP" : "UDP";

            int packets    = 5 + rand.nextInt(15);          // 5 to 19 packets
            int avgSize    = 400 + rand.nextInt(600);       // ordinary MTU-ish payloads
            int bytes      = packets * avgSize;
            int durationMs = 500 + rand.nextInt(2500);      // 0.5s to 3s conversations

            row(csv, src, dst, srcPort, dstPort, proto, packets, bytes, durationMs);
        }
        writeFile(TRAINING_FILE, csv.toString());
    }

    // Test data: normal background traffic plus a randomised mix of attack scenarios,
    // so the classifier has more than one kind of thing to find. Always at least one.
    static void generateTestCsv() {
        StringBuilder csv = new StringBuilder(CSV_HEADER);
        Random rand = new Random(); // random seed so results vary on each click

        // --- background: ordinary traffic, same shape as the training set ---
        int numNormal = 10 + rand.nextInt(10);              // 10 to 19 normal flows
        for (int i = 0; i < numNormal; i++) {
            String src     = "192.168.1." + (100 + rand.nextInt(50));
            String dst     = "10.0.0."    + (2 + rand.nextInt(8));
            int    srcPort = 50000 + rand.nextInt(10000);
            int    dstPort = rand.nextBoolean() ? 80 : 443;
            String proto   = rand.nextBoolean() ? "TCP" : "UDP";

            int packets    = 5 + rand.nextInt(15);
            int avgSize    = 400 + rand.nextInt(600);
            row(csv, src, dst, srcPort, dstPort, proto,
                packets, packets * avgSize, 500 + rand.nextInt(2500));
        }

        // Decide the attack mix, guaranteeing at least one attack in the scan.
        int floods = rand.nextInt(3);                       // 0 to 2
        int scans  = rand.nextInt(2);                       // 0 or 1
        int exfils = rand.nextInt(2);                       // 0 or 1
        int slows  = rand.nextInt(2);                       // 0 or 1
        if (floods + scans + exfils + slows == 0) floods = 1;

        // --- DoS flood: enormous packet count at one service, tiny packets ---
        for (int i = 0; i < floods; i++) {
            String src     = "192.168.1." + (200 + rand.nextInt(20));
            int    packets = 800 + rand.nextInt(5000);
            int    avgSize = 60 + rand.nextInt(80);         // SYN-flood sized
            row(csv, src, "10.0.0.5", 60000 + rand.nextInt(5000), 80, "TCP",
                packets, packets * avgSize, 200 + rand.nextInt(800));
        }

        // --- Port scan: one host sweeping many ports, a couple of packets each ---
        for (int i = 0; i < scans; i++) {
            String src       = "192.168.1." + (230 + rand.nextInt(10));
            int    numPorts  = 10 + rand.nextInt(7);        // 10 to 16 distinct ports
            Set<Integer> used = new HashSet<>();
            while (used.size() < numPorts) {
                used.add(1 + rand.nextInt(1024));           // well-known port range
            }
            for (int port : used) {
                int packets = 1 + rand.nextInt(3);          // 1 to 3 probe packets
                int avgSize = 40 + rand.nextInt(40);
                row(csv, src, "10.0.0.7", 40000 + rand.nextInt(20000), port, "TCP",
                    packets, packets * avgSize, 10 + rand.nextInt(40));
            }
        }

        // --- Exfiltration: normal packet COUNT, jumbo payloads, long transfer ---
        for (int i = 0; i < exfils; i++) {
            String src     = "192.168.1." + (150 + rand.nextInt(20));
            int    packets = 12 + rand.nextInt(8);          // stays inside the normal band
            int    avgSize = 8000 + rand.nextInt(7000);     // jumbo frames
            row(csv, src, "203.0.113." + (10 + rand.nextInt(40)),
                50000 + rand.nextInt(10000), 443, "TCP",
                packets, packets * avgSize, 5000 + rand.nextInt(15000));
        }

        // --- Low-and-slow probe: trickled out to stay under volume thresholds ---
        for (int i = 0; i < slows; i++) {
            String src     = "192.168.1." + (180 + rand.nextInt(10));
            int    packets = 4 + rand.nextInt(4);
            int    avgSize = 300 + rand.nextInt(200);
            row(csv, src, "10.0.0.3", 45000 + rand.nextInt(10000), 22, "TCP",
                packets, packets * avgSize, 40000 + rand.nextInt(120000));
        }

        writeFile(TEST_FILE, csv.toString());
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
