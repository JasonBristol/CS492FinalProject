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
  private int total, incoming, outgoing, iSYNnACK, oSYNACK, oRST, iSYNACK, oSYNnACK, iFIN, oFIN;
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
          ScanDetector(currentPacket);
        }
      }
    }
    appendLog(txtArea, "Terminating Analzyer Thread.", Color.DARK_GRAY);
  }
    private void ScanDetector(PcapPacket packet) {
        Tcp tcp = new Tcp();
        Ip4 ipv4 = new Ip4();
        InetAddress IP;
      try {
          if(packet.hasHeader(tcp)) {
              total++;
              IP = InetAddress.getLocalHost();
              if (org.jnetpcap.packet.format.FormatUtils.ip(packet.getHeader(ipv4).source()).equals(IP.getHostAddress())){
                  // check outgoing details
                  outgoing++;
                  if(packet.getHeader(tcp).flags_ACK() && packet.getHeader(tcp).flags_SYN()) oSYNACK++;
                  if(!packet.getHeader(tcp).flags_ACK() && packet.getHeader(tcp).flags_SYN()) oSYNnACK++;
                  if(packet.getHeader(tcp).flags_RST()) oRST++;
                  if(packet.getHeader(tcp).flags_FIN()) oFIN++;
              } else {
                  // check outgoing details
                  incoming++;
                  if(!packet.getHeader(tcp).flags_ACK() && packet.getHeader(tcp).flags_SYN()) iSYNnACK++;
                  if(packet.getHeader(tcp).flags_ACK() && packet.getHeader(tcp).flags_SYN()) iSYNACK++;
                  if(packet.getHeader(tcp).flags_FIN()) iFIN++;
              }
          }
          appendLog(txtArea, "c1: " + iSYNnACK + " c2:" + oSYNACK + " c3:" + oRST + " c4:" + oSYNnACK + " c5:" + iSYNACK + " c6:" + oFIN + " c7:" + iFIN + " p1:" + P1 +  " p2:" + P2 + " p3:" + P3 + "\n", Color.black);
          //appendLog(txtArea, "incoming: " + incoming + "\toutgoing: " + outgoing + "\t " + IP.getHostAddress() + "\t " +  org.jnetpcap.packet.format.FormatUtils.ip(packet.getHeader(ipv4).source()) + "\n", Color.red);
      } catch (UnknownHostException ex) {
          Logger.getLogger(PacketHeaderAnalyzer.class.getName()).log(Level.SEVERE, null, ex);
      }
        /*
        if (org.jnetpcap.packet.format.FormatUtils.ip(packet.getHeader(ipv4).source()).equals("192.168.0.2") || org.jnetpcap.packet.format.FormatUtils.ip(packet.getHeader(ipv4).source()).equals("192.168.0.3")) {
            appendLog(txtArea, "Source: " + org.jnetpcap.packet.format.FormatUtils.ip(packet.getHeader(ipv4).source()) + "\n", Color.red);
        }*/
    }
    
    private void checkTcpFlags(PcapPacket packet){
        Tcp tcp = new Tcp();
        Ip4 ipv4 = new Ip4();
        //WORK IN PROGRESS

        // SYN and URG invalid
        if(packet.getHeader(tcp).flags_SYN() && packet.getHeader(tcp).flags_URG() ) {
            appendLog(txtArea, org.jnetpcap.packet.format.FormatUtils.ip(packet.getHeader(ipv4).source()) + " is Suspicious 001\n", Color.black
            );
        }
        // SYN and PSH invalid
        if(packet.getHeader(tcp).flags_SYN() && packet.getHeader(tcp).flags_PSH() ) {
            appendLog(txtArea, org.jnetpcap.packet.format.FormatUtils.ip(packet.getHeader(ipv4).source()) + " is Suspicious 002\n",Color.black);
        }
        // SYN and FIN and RST
        if(packet.getHeader(tcp).flags_SYN() && packet.getHeader(tcp).flags_FIN() && packet.getHeader(tcp).flags_RST() ) {
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
