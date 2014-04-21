/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package cs492finalproject.Networking;

import java.util.Date;
import java.util.List;
import javax.swing.JComboBox;
import javax.swing.JTextArea;
import javax.swing.JToggleButton;
import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;

/**
 *
 * @author JGR
 */
public class PacketCapture implements Runnable {

  private JToggleButton tbtnCapture;
  private JTextArea txtaLog;
  private Pcap pcap;
  private JComboBox cboxDevice;
  private List<PcapIf> alldevs;
  private StringBuilder errbuf;
  private final int userVal;
  private final int numPackets;
  private volatile boolean isCapturing;

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
      txtaLog.append("\nBeginning Packet Capture ["
          + ((userVal == 0) ? "Infinity" : userVal) + "]:\n\n");
      txtaLog.setCaretPosition(txtaLog.getText().length());
      int snaplen = 64 * 1024;           // Capture all packets, no trucation  
      int flags = Pcap.MODE_PROMISCUOUS; // capture all packets  
      int timeout = 10 * 1000;           // 10 seconds in millis    
      pcap = Pcap.openLive(
          alldevs.get(
              cboxDevice.getSelectedIndex()).getName(), snaplen, flags, timeout, errbuf);

      if (pcap == null) {
        txtaLog.append("Error while opening device for capture: " + errbuf.toString() + "\n");
        txtaLog.setCaretPosition(txtaLog.getText().length());
        return;
      }

      PcapPacketHandler<String> jpacketHandler = new PcapPacketHandler<String>() {
        @Override
        public void nextPacket(final PcapPacket packet, final String user) {
          if (!isCapturing) {
            pcap.breakloop(); // Break the loop and exit
          }
          txtaLog.append("Received packet at " + new Date(packet.getCaptureHeader().timestampInMillis())
              + "\tcaplen=" + packet.getCaptureHeader().caplen()
              + "\tlen=" + packet.getCaptureHeader().wirelen()
              + "\t" + user + "\n");
          txtaLog.setCaretPosition(txtaLog.getText().length());
        }
      };

      pcap.loop(numPackets, jpacketHandler, "IDS System");

      txtaLog.append("\nCapture finished. Link to PCAP closed.\n");
      txtaLog.setCaretPosition(txtaLog.getText().length());
      isCapturing = false;
      tbtnCapture.setSelected(false);
    }
    // Clean up after stop requested.
    try {
      pcap.close();
    } catch (Exception e) {
      txtaLog.append("Link to PCAP won't close, trying again...\n");
      txtaLog.setCaretPosition(txtaLog.getText().length());
    }
  }

  public void setCapturing(boolean isCapturing) {
    this.isCapturing = isCapturing;
  }
  
}
