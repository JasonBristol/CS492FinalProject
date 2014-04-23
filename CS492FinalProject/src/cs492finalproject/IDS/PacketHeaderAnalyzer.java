/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package cs492finalproject.IDS;

import cs492finalproject.Interfaces.LogInterface;
import java.awt.Color;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.LinkedList;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.swing.JTextPane;
import javax.swing.text.SimpleAttributeSet;
import javax.swing.text.StyleConstants;
import javax.swing.text.StyledDocument;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.Tcp;

/**
 *
 * @author JBristol
 */
public class PacketHeaderAnalyzer implements Runnable, LogInterface {

  private final LinkedList<PcapPacket> packets;
  private final JTextPane txtArea;
  private int incoming, outgoing, incomingSYN, outgoingSYN, outgoingRST, incomingSYNACK, outgoingSYNACK, incomingFIN, outgoingFIN;
  private int incomingACK, outgoingACK, incomingPSHACK, outgoingPSHACK;
  private double P2;
  private int P1, P3;

  public PacketHeaderAnalyzer(JTextPane txtArea) {
    this.txtArea = txtArea;
    packets = new LinkedList<PcapPacket>();

  }

  @Override
  public void run() {
    Tcp tcp = new Tcp();
    Ip4 ipv4 = new Ip4();
    while (!Thread.interrupted()) {
      if (!packets.isEmpty()) {
        PcapPacket currentPacket = packets.removeFirst();
        if (currentPacket.hasHeader(tcp)) {
          //checkTcpFlags(currentPacket);
          SYNScan(currentPacket);
        }
      }
    }
    appendLog(txtArea, "Terminating Analzyer Thread.", Color.DARK_GRAY);
  }

  private void SYNScan(PcapPacket packet) {
    Tcp tcp = new Tcp();
    Ip4 ipv4 = new Ip4();
    InetAddress IP;
    try {
      IP = InetAddress.getLocalHost();
      if (org.jnetpcap.packet.format.FormatUtils.ip(packet.getHeader(ipv4).source()).equals(IP.getHostAddress())) {
        // check outgoing details
        if (packet.hasHeader(tcp)) {
          outgoing++;
          if (packet.getHeader(tcp).flags_ACK() && packet.getHeader(tcp).flags_SYN()) {
            outgoingSYNACK++;
          }
          if (packet.getHeader(tcp).flags_ACK() && packet.getHeader(tcp).flags_PSH()) {
            outgoingPSHACK++;
          }
          if (packet.getHeader(tcp).flags_RST()) {
            outgoingRST++;
          }
          if (packet.getHeader(tcp).flags_SYN()) {
            outgoingSYN++;
          }
          if (packet.getHeader(tcp).flags_FIN()) {
            outgoingFIN++;
          }
          if (packet.getHeader(tcp).flags_ACK() && !packet.getHeader(tcp).flags_PSH() && !packet.getHeader(tcp).flags_SYN()) {
            outgoingACK++;
          }
        }
      } else {
        // check outgoing details
        if (packet.hasHeader(tcp)) {
          incoming++;
          if (packet.getHeader(tcp).flags_ACK() && packet.getHeader(tcp).flags_SYN()) {
            incomingSYNACK++;
          }
          if (packet.getHeader(tcp).flags_ACK() && packet.getHeader(tcp).flags_PSH()) {
            incomingPSHACK++;
          }
          if (packet.getHeader(tcp).flags_SYN()) {
            incomingSYN++;
          }
          if (packet.getHeader(tcp).flags_FIN()) {
            incomingFIN++;
          }
          if (packet.getHeader(tcp).flags_ACK() && !packet.getHeader(tcp).flags_PSH() && !packet.getHeader(tcp).flags_SYN()) {
            incomingACK++;
          }
        }
      }
      P1 = incomingSYN - outgoingSYNACK;
      P2 = outgoingRST / ((incoming + outgoing) - (incomingACK + outgoingACK + incomingPSHACK + outgoingPSHACK));
      P3 = (incomingSYN - ((incomingFIN >= outgoingFIN) ? incomingFIN : outgoingFIN));
      appendLog(txtArea, "c1: " + incomingSYN + " c2:" + outgoingSYNACK + " c3:" + outgoingRST + " c4:" + outgoingSYN + " c5:" + incomingSYNACK + " c6:" + outgoingFIN + " c7:" + incomingFIN + " p1:" + P1 + " p2:" + P2 + " p3:" + P3 + "\n", Color.black);
      //appendLog(txtArea, "incoming: " + incoming + "\toutgoing: " + outgoing + "\t " + IP.getHostAddress() + "\t " +  org.jnetpcap.packet.format.FormatUtils.ip(packet.getHeader(ipv4).source()) + "\n", Color.red);
    } catch (UnknownHostException ex) {
      Logger.getLogger(PacketHeaderAnalyzer.class.getName()).log(Level.SEVERE, null, ex);
    }
    /*
     if (org.jnetpcap.packet.format.FormatUtils.ip(packet.getHeader(ipv4).source()).equals("192.168.0.2") || org.jnetpcap.packet.format.FormatUtils.ip(packet.getHeader(ipv4).source()).equals("192.168.0.3")) {
     appendLog(txtArea, "Source: " + org.jnetpcap.packet.format.FormatUtils.ip(packet.getHeader(ipv4).source()) + "\n", Color.red);
     }*/
  }

  private void checkTcpFlags(PcapPacket packet) {
    Tcp tcp = new Tcp();
    Ip4 ipv4 = new Ip4();
        //WORK IN PROGRESS

    // SYN and URG invalid
    if (packet.getHeader(tcp).flags_SYN() && packet.getHeader(tcp).flags_URG()) {
      appendLog(txtArea, org.jnetpcap.packet.format.FormatUtils.ip(packet.getHeader(ipv4).source()) + " is Suspicious 001\n", Color.black
      );
    }
    // SYN and PSH invalid
    if (packet.getHeader(tcp).flags_SYN() && packet.getHeader(tcp).flags_PSH()) {
      appendLog(txtArea, org.jnetpcap.packet.format.FormatUtils.ip(packet.getHeader(ipv4).source()) + " is Suspicious 002\n", Color.black);
    }
    // SYN and FIN and RST
    if (packet.getHeader(tcp).flags_SYN() && packet.getHeader(tcp).flags_FIN() && packet.getHeader(tcp).flags_RST()) {
      appendLog(txtArea, org.jnetpcap.packet.format.FormatUtils.ip(packet.getHeader(ipv4).source()) + " is Suspicious 003\n", Color.black);
    }
  }

  public void addPacket(PcapPacket packet) {
    packets.add(packet);
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
