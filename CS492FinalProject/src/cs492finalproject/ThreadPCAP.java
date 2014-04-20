/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

package cs492finalproject;

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
public class ThreadPCAP implements Runnable {
    
    JToggleButton tbtnCapture;
    JTextArea txtaLog;
    Pcap pcap;
    JComboBox cboxDevice;
    List<PcapIf> alldevs;
    StringBuilder errbuf;
    final int userVal;
    final int numPackets;
            
    public ThreadPCAP(int userVal, int numPackets, JToggleButton tbtnCapture, JTextArea txtaLog, Pcap pcap, JComboBox cboxDevice, List<PcapIf> alldevs, StringBuilder errbuf) {
        this.userVal = userVal;
        this.numPackets = numPackets;
        this.tbtnCapture = tbtnCapture;
        this.txtaLog = txtaLog;
        this.pcap = pcap;
        this.cboxDevice = cboxDevice;
        this.alldevs = alldevs;
        this.errbuf = errbuf;
        
    }

    public void run() {
          while (tbtnCapture.isSelected()) {
            txtaLog.append("\nBeginning Packet Capture ["
                + ((userVal == 0) ? "Infinity" : userVal) + "]:\n\n");
            int snaplen = 64 * 1024;           // Capture all packets, no trucation  
            int flags = Pcap.MODE_PROMISCUOUS; // capture all packets  
            int timeout = 10 * 1000;           // 10 seconds in millis    
            pcap = Pcap.openLive(
                alldevs.get(
                    cboxDevice.getSelectedIndex()).getName(), snaplen, flags, timeout, errbuf);

            if (pcap == null) {
              txtaLog.append("Error while opening device for capture: " + errbuf.toString() + "\n");
              return;
            }

            PcapPacketHandler<String> jpacketHandler = new PcapPacketHandler<String>() {
              @Override
              public void nextPacket(final PcapPacket packet, final String user) {
                txtaLog.append("Received packet at " + new Date(packet.getCaptureHeader().timestampInMillis())
                    + "\tcaplen=" + packet.getCaptureHeader().caplen()
                    + "\tlen=" + packet.getCaptureHeader().wirelen()
                    + "\t" + user + "\n");
              }
            };

            pcap.loop(numPackets, jpacketHandler, "IDS System");

            txtaLog.append("\nCapture finished. Closing link to PCAP.\n");
            tbtnCapture.setSelected(false);
          }
          // Clean up after stop requested.
          try {
            pcap.close();
          } catch (Exception e) {
            txtaLog.append("Link to PCAP is already closed, trying anyway.\n");
          }
    }
}

