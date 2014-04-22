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

  public PacketHeaderAnalyzer(JTextPane txtArea) {
    this.txtArea = txtArea;
    packets = new LinkedList<PcapPacket>();
    incoming = 0;
    outgoing = 0;

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
    appendLog(txtArea, "Terminating Analzyer Thread.", Color.BLACK);
  }
    private void SYNScan(PcapPacket packet) {
        Tcp tcp = new Tcp();
        Ip4 ipv4 = new Ip4();
        InetAddress IP;
      try {
          IP = InetAddress.getLocalHost();
          if (org.jnetpcap.packet.format.FormatUtils.ip(packet.getHeader(ipv4).source()).equals(IP.getHostAddress())){
              outgoing++;
          } else {
              incoming++;
          }
          appendLog(txtArea, "incoming: " + incoming + "\toutgoing: " + outgoing + "\t " + IP.getHostAddress() + "\t " +  org.jnetpcap.packet.format.FormatUtils.ip(packet.getHeader(ipv4).source()) + "\n", Color.red);
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
    log.setCaretPosition(0);
  }
}
