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
        }
      }
    }
    appendLog(txtArea, "Terminating Analzyer Thread.");
  }

  private void checkTcpFlags(PcapPacket packet) {

    // Initialize headers
    Tcp tcp = new Tcp();
    Ip4 ipv4 = new Ip4();

    //WORK IN PROGRESS
    if (packet.getHeader(tcp).flags_ACK()) {
      //appendLog(txtArea, org.jnetpcap.packet.format.FormatUtils.ip(packet.getHeader(ipv4).source()) + "is ACK \n");
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
