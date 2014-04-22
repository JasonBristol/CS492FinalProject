/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package cs492finalproject.IDS;

import cs492finalproject.Interfaces.LogInterface;
import java.util.LinkedList;
import javax.swing.JTextArea;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.Tcp;

/**
 *
 * @author JBristol
 */
public class PacketHeaderAnalyzer implements Runnable, LogInterface {

  private final LinkedList<PcapPacket> packets;
  private final JTextArea txtArea;

  public PacketHeaderAnalyzer(JTextArea txtArea) {
    this.txtArea = txtArea;
    packets = new LinkedList<PcapPacket>();

  }

  @Override
  public void run() {
    Tcp tcp = new Tcp();
    while (!Thread.interrupted()) {
      if (!packets.isEmpty()) {
        PcapPacket currentPacket = packets.removeFirst();
        if (currentPacket.hasHeader(tcp)) {
          checkTcpFlags(currentPacket);
          checkHeaderSize(currentPacket);
        }
      }
    }
  }
    private void checkHeaderSize(PcapPacket packet) {
        Tcp tcp = new Tcp();
        Ip4 ipv4 = new Ip4();
        appendLog(txtArea, "Header Length " + packet.getHeader(tcp).getHeaderLength() + "\n") ;
    }
    
    private void checkTcpFlags(PcapPacket packet){
        Tcp tcp = new Tcp();
        Ip4 ipv4 = new Ip4();
        //WORK IN PROGRESS

        // SYN and URG invalid
        if(packet.getHeader(tcp).flags_SYN() && packet.getHeader(tcp).flags_URG() ) {
            appendLog(txtArea, org.jnetpcap.packet.format.FormatUtils.ip(packet.getHeader(ipv4).source()) + " is Suspicious 001\n");
        }
        // SYN and PSH invalid
        if(packet.getHeader(tcp).flags_SYN() && packet.getHeader(tcp).flags_PSH() ) {
            appendLog(txtArea, org.jnetpcap.packet.format.FormatUtils.ip(packet.getHeader(ipv4).source()) + " is Suspicious 002\n");
        }
        // SYN and FIN and RST
        if(packet.getHeader(tcp).flags_SYN() && packet.getHeader(tcp).flags_FIN() && packet.getHeader(tcp).flags_RST() ) {
            appendLog(txtArea, org.jnetpcap.packet.format.FormatUtils.ip(packet.getHeader(ipv4).source()) + " is Suspicious 003\n");
        }
    }


  public void addPacket(PcapPacket packet) {
    packets.add(packet);
  }

  @Override
  public void appendLog(JTextArea log, String message) {
    log.append(message);
    log.setCaretPosition(log.getText().length());
  }
}
