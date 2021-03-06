package cs492finalproject.IDS;

import cs492finalproject.Interfaces.LogInterface;
import java.awt.Color;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import javax.swing.JComboBox;
import javax.swing.JTextField;
import javax.swing.JTextPane;
import javax.swing.JToggleButton;
import javax.swing.text.SimpleAttributeSet;
import javax.swing.text.StyleConstants;
import javax.swing.text.StyledDocument;
import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.Tcp;

/**
 *
 * @author JBristol
 */
public class PacketCapture implements Runnable, LogInterface {

  private final JToggleButton tbtnCapture;
  private final JTextPane txtaLog;
  private Pcap pcap;
  private final JComboBox cboxDevice;
  private final List<PcapIf> alldevs;
  private final StringBuilder errbuf;
  private final int userVal;
  private final int numPackets;
  private volatile boolean isCapturing;
  private final SimpleDateFormat dform = new SimpleDateFormat("MMM dd h:mm:ss a");
  private PacketHeaderAnalyzer PHA;
  private final ArrayList<Integer> ip_port_hashes;
  private final JTextField[] packetFields;
  private InetAddress inet;

  public PacketCapture(final int userVal, final int numPackets, JToggleButton tbtnCapture,
      JTextPane txtaLog, Pcap pcap, JComboBox cboxDevice, List<PcapIf> alldevs, StringBuilder errbuf, JTextField[] packetFields) {
    this.userVal = userVal;
    this.numPackets = numPackets;
    this.tbtnCapture = tbtnCapture;
    this.txtaLog = txtaLog;
    this.pcap = pcap;
    this.cboxDevice = cboxDevice;
    this.alldevs = alldevs;
    this.errbuf = errbuf;
    this.isCapturing = false;
    this.ip_port_hashes = new ArrayList<Integer>();
    this.packetFields = packetFields;
  }

  @Override
  public void run() {
    // Create Analyzer Thread
    PHA = new PacketHeaderAnalyzer(txtaLog, packetFields);
    Thread analyzer = new Thread(PHA);
    analyzer.start();

    while (isCapturing) { // Don't do anything unless isCapturing is true
      appendLog(txtaLog, "\nBeginning Packet Capture ["
          + ((userVal == 0) ? "Infinity" : userVal) + "]:\n\n", Color.DARK_GRAY);
      int snaplen = 64 * 1024;           // Capture all packets, no trucation  
      int flags = Pcap.MODE_PROMISCUOUS; // capture all packets  
      int timeout = 10 * 1000;           // 10 seconds in millis    
      pcap = Pcap.openLive(
          alldevs.get(
              cboxDevice.getSelectedIndex()).getName(), snaplen, flags, timeout, errbuf);

      if (pcap == null) {
        appendLog(txtaLog, "Error while opening device for capture: " + errbuf.toString() + "\n", Color.RED);
        return;
      }

      PcapPacketHandler<String> jpacketHandler = new PcapPacketHandler<String>() {

        // Initialize headers
        Tcp tcp = new Tcp();
        Ip4 ipv4 = new Ip4();

        // Initialize strings
        String srcIP = "", destIP = "", srcPort = "", destPort = "", sequence = "",
            ack = "", offset = "", flags = "", checksum = "", direction = "";

        @Override
        public void nextPacket(final PcapPacket packet, final String user) {
          if (!isCapturing) {
            pcap.breakloop(); // Break the loop and exit
          }

          // Add packet to Analzyer Thread
          PcapPacket clone = new PcapPacket(packet);
          PHA.addPacket(clone);

          if (packet.hasHeader(ipv4)) {
            // If it has an IPv4 header, lets clone that and build some strings
            packet.getHeader(ipv4);
            srcIP = org.jnetpcap.packet.format.FormatUtils.ip(packet.getHeader(ipv4).source());
            destIP = org.jnetpcap.packet.format.FormatUtils.ip(packet.getHeader(ipv4).destination());
          }

          if (packet.hasHeader(tcp)) {
            // If it has a TCP header, lets clone that and build some strings
            packet.getHeader(tcp);
            srcPort = ":" + String.valueOf(tcp.source());
            destPort = ":" + String.valueOf(tcp.destination());
            sequence = "seq=" + String.valueOf(tcp.seq());
            ack = "ack=" + String.valueOf(tcp.ack());
            offset = "offset=" + String.valueOf(tcp.getHeaderOffset());
            flags = "flags=" + String.valueOf(tcp.flags());
            checksum = "checksum=" + String.valueOf(tcp.checksum());

            // Store ip and port
            int hash = (srcIP + String.valueOf(tcp.destination())).hashCode();
            if (!ip_port_hashes.contains(hash)) {
              ip_port_hashes.add(hash);
            }
          }

          try {
            if (packet.hasHeader(tcp) && packet.hasHeader(ipv4)) {
              inet = InetAddress.getLocalHost();
              if (srcIP.equals(inet.getHostAddress())) {
                direction = "=====>";
              } else {
                direction = "<=====";
              }
            }
          } catch (UnknownHostException e) {
            appendLog(txtaLog, e.getMessage(), Color.RED);
          }

          // Capture header strings
          String date = dform.format(new Date(packet.getCaptureHeader().timestampInMillis()));

          appendLog(txtaLog, "#---| " + date
              + "\t" + srcIP + srcPort + "\t" + direction + "\t" + destIP + destPort
              + "\t" + sequence
              + "\t" + ack
              + "\t" + offset
              + "\t" + flags
              + "\t" + checksum
              + "\n", new Color(50, 148, 44));
        }
      };

      pcap.loop(numPackets, jpacketHandler, "IDS System");

      appendLog(txtaLog, "\nCapture finished. Link to PCAP closed.\n", Color.DARK_GRAY);

      isCapturing = false; // Stop processing
      tbtnCapture.setSelected(false); // Reset button
    }
    // Your here if isCapturing is false
    // Clean up and destroy threads.
    try {
      pcap.close(); // Close the connection
      analyzer.interrupt(); // Safely destroy the thread
      Thread.currentThread().interrupt(); // Safely destroy the thread
    } catch (Exception e) {
      appendLog(txtaLog, "Link to PCAP closing, waiting for stray packets...\n", Color.DARK_GRAY);
    }
  }

  public synchronized void setCapturing(boolean isCapturing) {
    this.isCapturing = isCapturing;
  }
  
  public void reset() {
    PHA.reset();
  }

  @Override
  public void appendLog(JTextPane log, String message, Color txtColor) {
    StyledDocument doc = log.getStyledDocument();
    SimpleAttributeSet aset = new SimpleAttributeSet();
    StyleConstants.setForeground(aset, txtColor);
    try {
      if (doc.getLength() == 0) {
        log.getDocument().insertString(0, message, aset);
      } else {
        log.getDocument().insertString(doc.getLength(), message, aset);
      }
    } catch (Exception e) {
      // Fail Silently
    }
    log.setCaretPosition(doc.getLength());
  }
}
