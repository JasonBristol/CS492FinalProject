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

  private JToggleButton tbtnCapture;
  private JTextArea txtaLog;
  private Pcap pcap;
  private JComboBox cboxDevice;
  private List<PcapIf> alldevs;
  private StringBuilder errbuf;
  private final int userVal;
  private final int numPackets;
  private volatile boolean isCapturing;
  private SimpleDateFormat dform = new SimpleDateFormat("MMM dd h:mm:ss a");

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
    while (isCapturing) {
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

        Tcp tcp = new Tcp();
        Ip4 ipv4 = new Ip4();

        byte[] dIP = new byte[4], sIP = new byte[4];
        String srcPort = "";
        String destPort = "";
        String sequence = "";

        @Override
        public void nextPacket(final PcapPacket packet, final String user) {
          if (!isCapturing) {
            pcap.breakloop(); // Break the loop and exit
          }

          if (packet.hasHeader(ipv4)) {
            dIP = packet.getHeader(ipv4).destination();
            sIP = packet.getHeader(ipv4).source();
          }
          
          if (packet.hasHeader(tcp)) {
            packet.getHeader(tcp);
            srcPort = ":" + String.valueOf(tcp.source());
            destPort = ":" + String.valueOf(tcp.destination());
            sequence = "seq=" + String.valueOf(tcp.seq());
          }

          String srcIP = org.jnetpcap.packet.format.FormatUtils.ip(sIP);
          String destIP = org.jnetpcap.packet.format.FormatUtils.ip(dIP);
          String date = dform.format(new Date(packet.getCaptureHeader().timestampInMillis()));

          appendLog(txtaLog, "#---| " + date
              + "\t" + srcIP + srcPort + "\t=====>\t" + destIP + destPort
//              + "\tcaplen=" + packet.getCaptureHeader().caplen()
//              + "\tlen=" + packet.getCaptureHeader().wirelen()
//              +"\tack=" + tcp.ack()
              + "\t" + sequence
              + "\n");
        }
      };

      pcap.loop(numPackets, jpacketHandler, "IDS System");

      appendLog(txtaLog, "\nCapture finished. Link to PCAP closed.\n");
      isCapturing = false;
      tbtnCapture.setSelected(false);
    }
    // Clean up after stop requested.
    try {
      pcap.close();
    } catch (Exception e) {
      appendLog(txtaLog, "Link to PCAP won't close, trying again...\n");
    }
  }

  public void setCapturing(boolean isCapturing) {
    this.isCapturing = isCapturing;
  }

  @Override
  public void appendLog(JTextArea log, String message) {
    log.append(message);
    log.setCaretPosition(log.getText().length());
  }
}
