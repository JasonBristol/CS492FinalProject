package cs492finalproject.IDS;

import cs492finalproject.Interfaces.LogInterface;
import java.awt.Color;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.LinkedList;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.swing.JTextField;
import javax.swing.JTextPane;
import javax.swing.text.BadLocationException;
import javax.swing.text.SimpleAttributeSet;
import javax.swing.text.StyleConstants;
import javax.swing.text.StyledDocument;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.Tcp;

/**
 *
 * @author JGR
 */
public class PacketHeaderAnalyzer implements Runnable, LogInterface {

  private final LinkedList<PcapPacket> packets;
  private final JTextPane txtArea;
  private int total, incoming, outgoing, iSYNnACK, oSYNACK, oRST,
      iSYNACK, oSYNnACK, iFIN, oFIN, iACK, oACK;
  private double P2;
  private int P1, P3;
  JTextField[] packetFields;

  public PacketHeaderAnalyzer(JTextPane txtArea, JTextField[] packetFields) {
    this.txtArea = txtArea;
    this.packets = new LinkedList<PcapPacket>();
    this.packetFields = packetFields;

  }

  @Override
  public void run() {
    Tcp tcp = new Tcp();
    Ip4 ipv4 = new Ip4();
    PcapPacket currentPacket = null;
    while (!Thread.interrupted()) {
      if (packets.peekFirst() != null) currentPacket = packets.removeFirst();
      if (currentPacket != null) ScanDetector(currentPacket);
      
    }
    appendLog(txtArea, "Terminating Analyzer Thread.", Color.DARK_GRAY);
  }

  private void ScanDetector(PcapPacket packet) {
    Tcp tcp = new Tcp();
    Ip4 ipv4 = new Ip4();
    InetAddress IP;
    try {
      if (packet.hasHeader(tcp) && packet.hasHeader(ipv4)) {
        total++;
        IP = InetAddress.getLocalHost();
        if (org.jnetpcap.packet.format.FormatUtils.ip(packet.getHeader(ipv4).source()).equals(IP.getHostAddress())) {
          // check outgoing details
          outgoing++;
          if (packet.getHeader(tcp).flags_ACK() && packet.getHeader(tcp).flags_SYN()) {
            oSYNACK++;
          }
          if (!packet.getHeader(tcp).flags_ACK() && packet.getHeader(tcp).flags_SYN()) {
            oSYNnACK++;
          }
          if (packet.getHeader(tcp).flags_RST()) {
            oRST++;
          }
          if (packet.getHeader(tcp).flags_FIN()) {
            oFIN++;
          }
          if (packet.getHeader(tcp).flags_ACK() && !packet.getHeader(tcp).flags_SYN()) {
            oACK++;
          }
        }

        if (org.jnetpcap.packet.format.FormatUtils.ip(packet.getHeader(ipv4).destination()).equals(IP.getHostAddress())) {
          // check incoming details
          incoming++;
          if (!packet.getHeader(tcp).flags_ACK() && packet.getHeader(tcp).flags_SYN()) {
            iSYNnACK++;
          }
          if (packet.getHeader(tcp).flags_ACK() && packet.getHeader(tcp).flags_SYN()) {
            iSYNACK++;
          }
          if (packet.getHeader(tcp).flags_FIN()) {
            iFIN++;
          }
          if (packet.getHeader(tcp).flags_ACK() && !packet.getHeader(tcp).flags_SYN()) {
            iACK++;
          }
        }
      }

//      appendLog(txtArea, "t:" + total + " i:" + incoming + " o:" + outgoing + " c1:" + iSYNnACK + " c2:"
//          + oSYNACK + " c3:" + oRST + " c4:" + oSYNnACK + " c5:" + iSYNACK + " c6:" + oFIN + " c7:"
//          + iFIN + " p1:" + P1 + " p2:" + P2 + " p3:" + P3 + "\n", Color.black);

      //Update Anomaly Detection Panel
      P1 = iSYNnACK - oSYNACK;
      if ((total - (iACK + oACK)) != 0) {
        P2 = (double) oRST / (total - (iACK + oACK));
      }

      P3 = (iSYNnACK + oSYNnACK) - ((iFIN > oFIN) ? iFIN : oFIN);

      packetFields[0].setText(total + "");
      packetFields[1].setText(incoming + "");
      packetFields[2].setText(iSYNnACK + "");
      packetFields[3].setText(iSYNACK + "");
      packetFields[4].setText(iFIN + "");
      packetFields[5].setText(outgoing + "");
      packetFields[6].setText(oSYNnACK + "");
      packetFields[7].setText(oSYNACK + "");
      packetFields[8].setText(oRST + "");
      packetFields[9].setText(oFIN + "");
      packetFields[10].setText(P1 + "");
      packetFields[11].setText(P2 + "");
      packetFields[12].setText(P3 + "");

      //Check For Anomalies
      //  SYN SCAN, 500 should be a ratio between a threshold and time the IDS has been active
      if (P2 > Double.parseDouble(packetFields[13].getText()) && P3 > 500) {
        packetFields[15].setText("Possible TCP SYN Scan in progress.");
      }
      //  FIN SCAN, -500 should be a ratio between a threshold and time the IDS has been active
      if (P2 > Double.parseDouble(packetFields[13].getText()) && P3 < -500) {
        packetFields[15].setText("Possible TCP FIN Scan in progress.");
      }

    } catch (UnknownHostException ex) {
      Logger.getLogger(PacketHeaderAnalyzer.class.getName()).log(Level.SEVERE, null, ex);
    }
  }

  public void addPacket(PcapPacket packet) {
    packets.add(packet);
  }
  
  public void reset() {
    P1 = 0;
    P2 = 0;
    P3 = 0;
    iACK = 0;
    iFIN = 0;
    iSYNACK = 0;
    iSYNnACK = 0;
    incoming = 0;
    oACK = 0;
    oFIN = 0;
    oRST = 0;
    oSYNACK = 0;
    oSYNnACK = 0;
    outgoing = 0;
    total = 0;
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
    } catch (BadLocationException e) {
      // Fail silently
    }
    log.setCaretPosition(doc.getLength());
  }
}
