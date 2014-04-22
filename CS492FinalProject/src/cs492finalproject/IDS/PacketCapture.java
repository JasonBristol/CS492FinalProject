/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package cs492finalproject.IDS;

import cs492finalproject.Interfaces.LogInterface;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.List;
import javax.swing.JComboBox;
import javax.swing.JTextArea;
import javax.swing.JToggleButton;
import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.Tcp;

/**
 *
 * @author JGR
 */
public class PacketCapture implements Runnable, LogInterface {

  private final JToggleButton tbtnCapture;
  private final JTextArea txtaLog;
  private Pcap pcap;
  private final JComboBox cboxDevice;
  private final List<PcapIf> alldevs;
  private final StringBuilder errbuf;
  private final int userVal;
  private final int numPackets;
  private volatile boolean isCapturing;
  private final SimpleDateFormat dform = new SimpleDateFormat("MMM dd h:mm:ss a");

  public PacketCapture(final int userVal, final int numPackets, JToggleButton tbtnCapture,
      JTextArea txtaLog, Pcap pcap, JComboBox cboxDevice, List<PcapIf> alldevs, StringBuilder errbuf) {
    this.userVal = userVal;
    this.numPackets = numPackets;
    this.tbtnCapture = tbtnCapture;
    this.txtaLog = txtaLog;
    this.pcap = pcap;
    this.cboxDevice = cboxDevice;
    this.alldevs = alldevs;
    this.errbuf = errbuf;
    this.isCapturing = false;
  }

  @Override
  public void run() {
    while (isCapturing) { // Don't do anything unless isCapturing is true
      appendLog(txtaLog, "\nBeginning Packet Capture ["
          + ((userVal == 0) ? "Infinity" : userVal) + "]:\n\n");
      int snaplen = 64 * 1024;           // Capture all packets, no trucation  
      int flags = Pcap.MODE_PROMISCUOUS; // capture all packets  
      int timeout = 10 * 1000;           // 10 seconds in millis    
      pcap = Pcap.openLive(
          alldevs.get(
              cboxDevice.getSelectedIndex()).getName(), snaplen, flags, timeout, errbuf);

      if (pcap == null) {
        appendLog(txtaLog, "Error while opening device for capture: " + errbuf.toString() + "\n");
        return;
      }

      PcapPacketHandler<String> jpacketHandler = new PcapPacketHandler<String>() {

        // Initialize headers
        Tcp tcp = new Tcp();
        Ip4 ipv4 = new Ip4();

        // Initialize strings
        String srcIP = "", destIP = "", srcPort = "", destPort = "", sequence = "";

        @Override
        public void nextPacket(final PcapPacket packet, final String user) {
          if (!isCapturing) {
            pcap.breakloop(); // Break the loop and exit
          }

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
          }

          // Capture header strings
          String date = dform.format(new Date(packet.getCaptureHeader().timestampInMillis()));

          appendLog(txtaLog, "#---| " + date
              + "\t" + srcIP + srcPort + "\t=====>\t" + destIP + destPort
              + "\t" + sequence
              + "\n");
        }
      };

      pcap.loop(numPackets, jpacketHandler, "IDS System");

      appendLog(txtaLog, "\nCapture finished. Link to PCAP closed.\n");
      
      isCapturing = false; // Stop processing
      tbtnCapture.setSelected(false); // Reset button
    }
    // Your here if isCapturing is false
    // Clean up and destroy thread.
    try {
      pcap.close(); // Close the connection
      Thread.currentThread().interrupt(); // Safely destroy the thread
    } catch (Exception e) {
      appendLog(txtaLog, "Link to PCAP closing, waiting for stray packets...\n");
    }
  }

  public synchronized void setCapturing(boolean isCapturing) {
    this.isCapturing = isCapturing;
  }

  @Override
  public void appendLog(JTextArea log, String message) {
    log.append(message);
    log.setCaretPosition(log.getText().length());
  }
}
