import cic.cs.unb.ca.jnetpcap.BasicFlow;
import cic.cs.unb.ca.jnetpcap.BasicPacketInfo;
import cic.cs.unb.ca.jnetpcap.FlowFeature;
import cic.cs.unb.ca.jnetpcap.PacketReader;
import org.jnetpcap.PcapClosedException;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

/**
 * CICFlowMeter over one endless capture: every flow is written the moment it is final.
 *
 * Usage:  java -cp <CICFlowMeter classpath>:<dir of this class> StreamMeter <capture or FIFO> <output CSV, or - for stdout>
 *
 * CICFlowMeter's own command line (ifm.Cmd) closes a flow only when that flow's next packet arrives or the input ends,
 * so on an input that never ends a flow that simply goes quiet is never written. This keeps CICFlowMeter's flow logic
 * exactly -- the body of add() mirrors cic.cs.unb.ca.jnetpcap.FlowGenerator.addPacket line for line -- and adds one
 * thing: about once a second of capture time, every flow older than the flow timeout is written and dropped. That is
 * the flow CICFlowMeter itself would write when the flow's next packet arrived, or at the end of input: its content
 * cannot change after its start + timeout. The next packet of such a connection starts a new flow with the swept
 * flow's direction, as FlowGenerator's timeout branch does. Rows are therefore the ones a single batch run over the
 * whole capture writes (checked by tools/live/stream_check.py); only their order and timing differ.
 *
 * After each sweep it prints "NETWATCH_SWEPT <capture time in microseconds>": every flow that started more than the
 * flow timeout before that moment has been written by then. With output "-" the rows go to stdout too, in order, so a
 * reader knows every row before a marker is complete and nothing grows on disk.
 */
public class StreamMeter {
    static final long FLOW_TIMEOUT = 120000000L;       // ifm.Cmd's values, in microseconds
    static final long ACTIVITY_TIMEOUT = 5000000L;
    static final long SWEEP_EVERY = 1000000L;
    static final long FORGET_AFTER = 3600000000L;      // a swept flow's direction is kept this long for its successor

    final HashMap<String, BasicFlow> current = new HashMap<>();
    final HashMap<String, Object[]> swept = new HashMap<>();   // id -> {src, dst, srcPort, dstPort, sweptAt}
    final PrintWriter csv, markers;                    // the same writer when rows go to stdout
    long lastSweep = 0, lastForget = 0;               // capture times are epoch microseconds, so the first packet sweeps

    StreamMeter(PrintWriter csv, PrintWriter markers) {
        this.csv = csv;
        this.markers = markers;
    }

    void write(BasicFlow flow) {
        csv.println(flow.dumpFlowBasedFeaturesEx());
    }

    void add(BasicPacketInfo packet) {
        long now = packet.getTimeStamp();
        if (current.containsKey(packet.fwdFlowId()) || current.containsKey(packet.bwdFlowId())) {
            String id = current.containsKey(packet.fwdFlowId()) ? packet.fwdFlowId() : packet.bwdFlowId();
            BasicFlow flow = current.get(id);
            if ((now - flow.getFlowStartTime()) > FLOW_TIMEOUT) {                       // flow timeout
                if (flow.packetCount() > 1) {
                    write(flow);
                }
                current.remove(id);
                current.put(id, new BasicFlow(true, packet, flow.getSrc(), flow.getDst(), flow.getSrcPort(),
                                              flow.getDstPort()));
            } else if (packet.hasFlagFIN()) {                                           // FIN ends a TCP flow
                flow.addPacket(packet);
                write(flow);
                current.remove(id);
            } else {
                flow.updateActiveIdleTime(now, ACTIVITY_TIMEOUT);
                flow.addPacket(packet);
                current.put(id, flow);
            }
        } else {
            // The successor of a swept flow: FlowGenerator would still hold that flow and take the timeout branch.
            String id = swept.containsKey(packet.fwdFlowId()) ? packet.fwdFlowId()
                      : swept.containsKey(packet.bwdFlowId()) ? packet.bwdFlowId() : null;
            if (id != null) {
                Object[] was = swept.remove(id);
                current.put(id, new BasicFlow(true, packet, (byte[]) was[0], (byte[]) was[1], (int) was[2],
                                              (int) was[3]));
            } else {
                current.put(packet.fwdFlowId(), new BasicFlow(true, packet));
            }
        }
        if (now - lastSweep >= SWEEP_EVERY) {
            sweep(now);
        }
    }

    void sweep(long now) {
        lastSweep = now;
        for (Iterator<Map.Entry<String, BasicFlow>> it = current.entrySet().iterator(); it.hasNext(); ) {
            Map.Entry<String, BasicFlow> entry = it.next();
            BasicFlow flow = entry.getValue();
            if ((now - flow.getFlowStartTime()) > FLOW_TIMEOUT) {
                if (flow.packetCount() > 1) {
                    write(flow);
                }
                swept.put(entry.getKey(), new Object[]{flow.getSrc(), flow.getDst(), flow.getSrcPort(),
                                                       flow.getDstPort(), now});
                it.remove();
            }
        }
        if (now - lastForget >= FORGET_AFTER / 60) {                                   // bounded memory
            lastForget = now;
            swept.values().removeIf(was -> now - (long) was[4] > FORGET_AFTER);
        }
        csv.flush();
        markers.println("NETWATCH_SWEPT " + now);
        markers.flush();
    }

    void finish() {                                                                     // end of input: ifm.Cmd's dump
        for (BasicFlow flow : current.values()) {
            if (flow.packetCount() > 1) {
                write(flow);
            }
        }
        csv.flush();
        markers.println("NETWATCH_DONE");
        markers.flush();
    }

    public static void main(String[] args) throws IOException {
        if (args.length != 2) {
            System.err.println("usage: StreamMeter <capture or FIFO> <output CSV>");
            System.exit(2);
        }
        boolean toStdout = args[1].equals("-");
        boolean fresh = toStdout || !new File(args[1]).exists();
        PrintWriter csv = toStdout ? new PrintWriter(System.out) : new PrintWriter(new FileWriter(args[1], true));
        if (fresh) {
            csv.println(FlowFeature.getHeader());
        }
        StreamMeter meter = new StreamMeter(csv, toStdout ? csv : new PrintWriter(System.out));
        PacketReader reader = new PacketReader(args[0], true, false);                  // IPv4 only, as ifm.Cmd
        while (true) {
            BasicPacketInfo packet;
            try {
                packet = reader.nextPacket();
            } catch (PcapClosedException end) {
                break;
            }
            if (packet != null) {
                meter.add(packet);
            }
        }
        meter.finish();
        csv.close();
    }
}
