package cs492finalproject;

import cs492finalproject.Interfaces.LogInterface;
import cs492finalproject.IDS.PacketCapture;
import cs492finalproject.Utils.BoundsPopupMenuListener;
import java.awt.Color;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import javax.swing.JTextPane;
import javax.swing.SpinnerNumberModel;
import javax.swing.text.SimpleAttributeSet;
import javax.swing.text.StyleConstants;
import javax.swing.text.StyledDocument;

import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;

/**
 *
 * @author Jason
 */
public class MainFrame extends javax.swing.JFrame implements LogInterface {

  private List<PcapIf> alldevs = new ArrayList<PcapIf>(); // Will be filled with NICs  
  private StringBuilder errbuf = new StringBuilder(); // For any error msgs
  private PacketCapture tPCAP;
  private Pcap pcap;
  private int userVal;
  private int numPackets;

  public MainFrame() {
    initComponents();
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

  /**
   * This method is called from within the constructor to initialize the form.
   * WARNING: Do NOT modify this code. The content of this method is always
   * regenerated by the Form Editor.
   */
  @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        tbStatusBar = new javax.swing.JToolBar();
        lblStatus = new javax.swing.JLabel();
        filler2 = new javax.swing.Box.Filler(new java.awt.Dimension(0, 0), new java.awt.Dimension(0, 0), new java.awt.Dimension(32767, 0));
        pbarProgress = new javax.swing.JProgressBar();
        filler1 = new javax.swing.Box.Filler(new java.awt.Dimension(5, 0), new java.awt.Dimension(5, 0), new java.awt.Dimension(10, 32767));
        tabpaneMain = new javax.swing.JTabbedPane();
        panelCapturing = new javax.swing.JPanel();
        lblDevice = new javax.swing.JLabel();
        cboxDevice = new javax.swing.JComboBox();
        btnScan = new javax.swing.JButton();
        lblPacketNumber = new javax.swing.JLabel();
        spinPacketNumber = new javax.swing.JSpinner();
        tbtnCapture = new javax.swing.JToggleButton();
        panelFiltering = new javax.swing.JPanel();
        panelAnomaly = new javax.swing.JPanel();
        panelPHA = new javax.swing.JPanel();
        jLabel1 = new javax.swing.JLabel();
        jLabel2 = new javax.swing.JLabel();
        jLabel3 = new javax.swing.JLabel();
        jLabel4 = new javax.swing.JLabel();
        jLabel5 = new javax.swing.JLabel();
        jLabel6 = new javax.swing.JLabel();
        jLabel7 = new javax.swing.JLabel();
        jLabel8 = new javax.swing.JLabel();
        jLabel9 = new javax.swing.JLabel();
        jLabel10 = new javax.swing.JLabel();
        jScrollPane1 = new javax.swing.JScrollPane();
        txtTotal = new javax.swing.JTextPane();
        jScrollPane2 = new javax.swing.JScrollPane();
        txtIncoming = new javax.swing.JTextPane();
        jScrollPane3 = new javax.swing.JScrollPane();
        txtISyn = new javax.swing.JTextPane();
        jScrollPane4 = new javax.swing.JScrollPane();
        txtISynAck = new javax.swing.JTextPane();
        jScrollPane5 = new javax.swing.JScrollPane();
        txtIFin = new javax.swing.JTextPane();
        jScrollPane6 = new javax.swing.JScrollPane();
        txtOutgoing = new javax.swing.JTextPane();
        jScrollPane7 = new javax.swing.JScrollPane();
        txtOSyn = new javax.swing.JTextPane();
        jScrollPane8 = new javax.swing.JScrollPane();
        txtOSynAck = new javax.swing.JTextPane();
        jScrollPane9 = new javax.swing.JScrollPane();
        txtRST = new javax.swing.JTextPane();
        jScrollPane10 = new javax.swing.JScrollPane();
        txtOFin = new javax.swing.JTextPane();
        jLabel11 = new javax.swing.JLabel();
        jLabel12 = new javax.swing.JLabel();
        jScrollPane11 = new javax.swing.JScrollPane();
        synNormal = new javax.swing.JTextPane();
        jScrollPane12 = new javax.swing.JScrollPane();
        finNormal = new javax.swing.JTextPane();
        jLabel13 = new javax.swing.JLabel();
        jLabel14 = new javax.swing.JLabel();
        jScrollPane13 = new javax.swing.JScrollPane();
        p1 = new javax.swing.JTextPane();
        jScrollPane14 = new javax.swing.JScrollPane();
        p2 = new javax.swing.JTextPane();
        jLabel15 = new javax.swing.JLabel();
        jScrollPane15 = new javax.swing.JScrollPane();
        p3 = new javax.swing.JTextPane();
        spLog = new javax.swing.JScrollPane();
        txtaLog = new javax.swing.JTextPane();
        mbarMain = new javax.swing.JMenuBar();
        menuFile = new javax.swing.JMenu();
        menuItemExit = new javax.swing.JMenuItem();
        menuEdit = new javax.swing.JMenu();

        setDefaultCloseOperation(javax.swing.WindowConstants.EXIT_ON_CLOSE);
        setTitle("CS 492 - Host-Based IDS System");
        setMinimumSize(new java.awt.Dimension(750, 500));
        setName("frameMaine"); // NOI18N

        tbStatusBar.setBorder(javax.swing.BorderFactory.createEmptyBorder(1, 1, 1, 1));
        tbStatusBar.setFloatable(false);
        tbStatusBar.setRollover(true);

        lblStatus.setForeground(new java.awt.Color(50, 148, 44));
        lblStatus.setText("Ready");
        tbStatusBar.add(lblStatus);
        tbStatusBar.add(filler2);

        pbarProgress.setBorderPainted(false);
        pbarProgress.setDoubleBuffered(true);
        pbarProgress.setMinimumSize(new java.awt.Dimension(146, 14));
        tbStatusBar.add(pbarProgress);
        pbarProgress.setVisible(false);
        tbStatusBar.add(filler1);

        tabpaneMain.setTabPlacement(javax.swing.JTabbedPane.LEFT);
        tabpaneMain.setDoubleBuffered(true);

        lblDevice.setText("Hardware Device:");

        BoundsPopupMenuListener listener = new BoundsPopupMenuListener(true, false);

        cboxDevice.addPopupMenuListener (listener );
        cboxDevice.setPrototypeDisplayValue ("ItemWWW");

        btnScan.setText("Scan for Devices");
        btnScan.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnScanActionPerformed(evt);
            }
        });

        lblPacketNumber.setText("# of Packets (0 for infinity):");

        spinPacketNumber.setEditor(new javax.swing.JSpinner.NumberEditor(spinPacketNumber, ""));
        spinPacketNumber.setModel(new SpinnerNumberModel(0, 0, 1000, 1));

        tbtnCapture.setText("Packet Capture OFF");
        tbtnCapture.addChangeListener(new javax.swing.event.ChangeListener() {
            public void stateChanged(javax.swing.event.ChangeEvent evt) {
                tbtnCaptureStateChanged(evt);
            }
        });
        tbtnCapture.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                tbtnCaptureActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout panelCapturingLayout = new javax.swing.GroupLayout(panelCapturing);
        panelCapturing.setLayout(panelCapturingLayout);
        panelCapturingLayout.setHorizontalGroup(
            panelCapturingLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(panelCapturingLayout.createSequentialGroup()
                .addContainerGap()
                .addGroup(panelCapturingLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(panelCapturingLayout.createSequentialGroup()
                        .addComponent(lblDevice)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(cboxDevice, 0, 418, Short.MAX_VALUE)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(btnScan))
                    .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, panelCapturingLayout.createSequentialGroup()
                        .addGap(0, 0, Short.MAX_VALUE)
                        .addGroup(panelCapturingLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, panelCapturingLayout.createSequentialGroup()
                                .addComponent(lblPacketNumber)
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                .addComponent(spinPacketNumber, javax.swing.GroupLayout.PREFERRED_SIZE, 58, javax.swing.GroupLayout.PREFERRED_SIZE))
                            .addComponent(tbtnCapture, javax.swing.GroupLayout.Alignment.TRAILING, javax.swing.GroupLayout.PREFERRED_SIZE, 202, javax.swing.GroupLayout.PREFERRED_SIZE))))
                .addContainerGap())
        );
        panelCapturingLayout.setVerticalGroup(
            panelCapturingLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(panelCapturingLayout.createSequentialGroup()
                .addContainerGap()
                .addGroup(panelCapturingLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(cboxDevice, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(lblDevice)
                    .addComponent(btnScan))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, 29, Short.MAX_VALUE)
                .addGroup(panelCapturingLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(spinPacketNumber, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(lblPacketNumber))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(tbtnCapture, javax.swing.GroupLayout.PREFERRED_SIZE, 43, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addContainerGap())
        );

        tabpaneMain.addTab("Packet Capturing", panelCapturing);

        javax.swing.GroupLayout panelFilteringLayout = new javax.swing.GroupLayout(panelFiltering);
        panelFiltering.setLayout(panelFilteringLayout);
        panelFilteringLayout.setHorizontalGroup(
            panelFilteringLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGap(0, 647, Short.MAX_VALUE)
        );
        panelFilteringLayout.setVerticalGroup(
            panelFilteringLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGap(0, 143, Short.MAX_VALUE)
        );

        tabpaneMain.addTab("Packet Filtering", panelFiltering);

        javax.swing.GroupLayout panelAnomalyLayout = new javax.swing.GroupLayout(panelAnomaly);
        panelAnomaly.setLayout(panelAnomalyLayout);
        panelAnomalyLayout.setHorizontalGroup(
            panelAnomalyLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGap(0, 647, Short.MAX_VALUE)
        );
        panelAnomalyLayout.setVerticalGroup(
            panelAnomalyLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGap(0, 143, Short.MAX_VALUE)
        );

        tabpaneMain.addTab("Anomaly Detection", panelAnomaly);
        tabpaneMain.setEnabledAt(tabpaneMain.indexOfTab("Anomaly Detection"), false);

        jLabel1.setText("Total");

        jLabel2.setText("Incoming");

        jLabel3.setText("Outgoing");

        jLabel4.setText("SYN");

        jLabel5.setText("SYNACK");

        jLabel6.setText("SYN");

        jLabel7.setText("SYNACK");

        jLabel8.setText("RST");

        jLabel9.setText("FIN");

        jLabel10.setText("FIN");

        txtTotal.setEditable(false);
        txtTotal.setFont(new java.awt.Font("Tahoma", 0, 10)); // NOI18N
        txtTotal.setName("txtTcpTotal"); // NOI18N
        jScrollPane1.setViewportView(txtTotal);
        txtTotal.getAccessibleContext().setAccessibleName("txtTotal");

        txtIncoming.setEditable(false);
        txtIncoming.setFont(new java.awt.Font("Tahoma", 0, 10)); // NOI18N
        jScrollPane2.setViewportView(txtIncoming);

        txtISyn.setEditable(false);
        txtISyn.setFont(new java.awt.Font("Tahoma", 0, 10)); // NOI18N
        jScrollPane3.setViewportView(txtISyn);

        txtISynAck.setEditable(false);
        txtISynAck.setFont(new java.awt.Font("Tahoma", 0, 10)); // NOI18N
        jScrollPane4.setViewportView(txtISynAck);

        txtIFin.setEditable(false);
        txtIFin.setFont(new java.awt.Font("Tahoma", 0, 10)); // NOI18N
        jScrollPane5.setViewportView(txtIFin);

        txtOutgoing.setEditable(false);
        txtOutgoing.setFont(new java.awt.Font("Tahoma", 0, 10)); // NOI18N
        jScrollPane6.setViewportView(txtOutgoing);

        txtOSyn.setEditable(false);
        txtOSyn.setFont(new java.awt.Font("Tahoma", 0, 10)); // NOI18N
        jScrollPane7.setViewportView(txtOSyn);

        txtOSynAck.setEditable(false);
        txtOSynAck.setFont(new java.awt.Font("Tahoma", 0, 10)); // NOI18N
        jScrollPane8.setViewportView(txtOSynAck);

        txtRST.setEditable(false);
        txtRST.setFont(new java.awt.Font("Tahoma", 0, 10)); // NOI18N
        jScrollPane9.setViewportView(txtRST);

        txtOFin.setEditable(false);
        txtOFin.setFont(new java.awt.Font("Tahoma", 0, 10)); // NOI18N
        jScrollPane10.setViewportView(txtOFin);

        jLabel11.setText("SYN Scan Normal");

        jLabel12.setText("FIN Scan Normal");

        synNormal.setFont(new java.awt.Font("Tahoma", 0, 10)); // NOI18N
        jScrollPane11.setViewportView(synNormal);

        finNormal.setFont(new java.awt.Font("Tahoma", 0, 10)); // NOI18N
        jScrollPane12.setViewportView(finNormal);

        jLabel13.setText("iSYN - oSYNACK");

        jLabel14.setText("RST / (Total - ACK)");

        jScrollPane13.setViewportView(p1);

        jScrollPane14.setViewportView(p2);

        jLabel15.setText("iSYN - Max( iFin, oFin)");

        jScrollPane15.setViewportView(p3);

        javax.swing.GroupLayout panelPHALayout = new javax.swing.GroupLayout(panelPHA);
        panelPHA.setLayout(panelPHALayout);
        panelPHALayout.setHorizontalGroup(
            panelPHALayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(panelPHALayout.createSequentialGroup()
                .addContainerGap()
                .addGroup(panelPHALayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(panelPHALayout.createSequentialGroup()
                        .addGroup(panelPHALayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(jLabel1)
                            .addComponent(jScrollPane1, javax.swing.GroupLayout.PREFERRED_SIZE, 68, javax.swing.GroupLayout.PREFERRED_SIZE))
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addGroup(panelPHALayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(jLabel2)
                            .addComponent(jScrollPane2, javax.swing.GroupLayout.PREFERRED_SIZE, 64, javax.swing.GroupLayout.PREFERRED_SIZE))
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                        .addGroup(panelPHALayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(jLabel4)
                            .addComponent(jScrollPane3, javax.swing.GroupLayout.PREFERRED_SIZE, 46, javax.swing.GroupLayout.PREFERRED_SIZE))
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                        .addGroup(panelPHALayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(jLabel5)
                            .addComponent(jScrollPane4, javax.swing.GroupLayout.PREFERRED_SIZE, 48, javax.swing.GroupLayout.PREFERRED_SIZE)))
                    .addGroup(panelPHALayout.createSequentialGroup()
                        .addGroup(panelPHALayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addGroup(panelPHALayout.createSequentialGroup()
                                .addComponent(jLabel11)
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                                .addComponent(jScrollPane11, javax.swing.GroupLayout.PREFERRED_SIZE, 31, javax.swing.GroupLayout.PREFERRED_SIZE)
                                .addGap(18, 18, 18)
                                .addComponent(jLabel13)
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                .addComponent(jScrollPane13, javax.swing.GroupLayout.PREFERRED_SIZE, 36, javax.swing.GroupLayout.PREFERRED_SIZE))
                            .addGroup(panelPHALayout.createSequentialGroup()
                                .addComponent(jLabel12)
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                                .addComponent(jScrollPane12, javax.swing.GroupLayout.PREFERRED_SIZE, 48, javax.swing.GroupLayout.PREFERRED_SIZE)))
                        .addGap(0, 21, Short.MAX_VALUE)))
                .addGroup(panelPHALayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(panelPHALayout.createSequentialGroup()
                        .addGroup(panelPHALayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(jLabel9)
                            .addComponent(jScrollPane5, javax.swing.GroupLayout.PREFERRED_SIZE, 41, javax.swing.GroupLayout.PREFERRED_SIZE))
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                        .addGroup(panelPHALayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(jScrollPane6, javax.swing.GroupLayout.PREFERRED_SIZE, 43, javax.swing.GroupLayout.PREFERRED_SIZE)
                            .addComponent(jLabel3))
                        .addGap(18, 18, 18)
                        .addGroup(panelPHALayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(jScrollPane7)
                            .addComponent(jLabel6, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
                        .addGap(18, 18, 18)
                        .addGroup(panelPHALayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                            .addComponent(jLabel7, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                            .addComponent(jScrollPane8))
                        .addGap(18, 18, 18)
                        .addGroup(panelPHALayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                            .addComponent(jScrollPane9)
                            .addComponent(jLabel8, javax.swing.GroupLayout.DEFAULT_SIZE, 40, Short.MAX_VALUE))
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addGroup(panelPHALayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(jLabel10)
                            .addComponent(jScrollPane10, javax.swing.GroupLayout.PREFERRED_SIZE, 43, javax.swing.GroupLayout.PREFERRED_SIZE))
                        .addGap(42, 42, 42))
                    .addGroup(panelPHALayout.createSequentialGroup()
                        .addGap(29, 29, 29)
                        .addComponent(jLabel14)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(jScrollPane14, javax.swing.GroupLayout.PREFERRED_SIZE, 42, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                        .addComponent(jLabel15)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                        .addComponent(jScrollPane15, javax.swing.GroupLayout.PREFERRED_SIZE, 41, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addContainerGap(28, Short.MAX_VALUE))))
        );
        panelPHALayout.setVerticalGroup(
            panelPHALayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, panelPHALayout.createSequentialGroup()
                .addGap(2, 2, 2)
                .addGroup(panelPHALayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jLabel1)
                    .addComponent(jLabel2)
                    .addComponent(jLabel3)
                    .addComponent(jLabel4)
                    .addComponent(jLabel5)
                    .addComponent(jLabel6)
                    .addComponent(jLabel7)
                    .addComponent(jLabel9)
                    .addComponent(jLabel8, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addComponent(jLabel10))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(panelPHALayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                    .addComponent(jScrollPane1)
                    .addComponent(jScrollPane2, javax.swing.GroupLayout.DEFAULT_SIZE, 23, Short.MAX_VALUE)
                    .addComponent(jScrollPane6, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(jScrollPane7, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(jScrollPane8, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(jScrollPane9, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(jScrollPane4)
                    .addComponent(jScrollPane3)
                    .addComponent(jScrollPane10, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(jScrollPane5))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, 33, Short.MAX_VALUE)
                .addGroup(panelPHALayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(jScrollPane15, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(jScrollPane14, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addGroup(panelPHALayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                        .addGroup(panelPHALayout.createSequentialGroup()
                            .addGap(1, 1, 1)
                            .addComponent(jLabel15, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
                        .addComponent(jLabel11)
                        .addComponent(jScrollPane11)
                        .addComponent(jLabel13, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                        .addComponent(jLabel14, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                        .addComponent(jScrollPane13, javax.swing.GroupLayout.DEFAULT_SIZE, 23, Short.MAX_VALUE)))
                .addGap(18, 18, 18)
                .addGroup(panelPHALayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(jLabel12, javax.swing.GroupLayout.PREFERRED_SIZE, 23, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(jScrollPane12, javax.swing.GroupLayout.PREFERRED_SIZE, 24, javax.swing.GroupLayout.PREFERRED_SIZE)))
        );

        tabpaneMain.addTab("PHA", panelPHA);

        spLog.setAutoscrolls(true);

        txtaLog.setBackground(new java.awt.Color(204, 204, 255));
        txtaLog.setFont(new java.awt.Font("Monospaced", 0, 11)); // NOI18N
        txtaLog.setForeground(new java.awt.Color(51, 51, 51));
        txtaLog.setSelectionColor(new java.awt.Color(0, 153, 102));
        spLog.setViewportView(txtaLog);

        menuFile.setText("File");

        menuItemExit.setAccelerator(javax.swing.KeyStroke.getKeyStroke(java.awt.event.KeyEvent.VK_E, java.awt.event.InputEvent.CTRL_MASK));
        menuItemExit.setText("Exit");
        menuItemExit.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                menuItemExitActionPerformed(evt);
            }
        });
        menuFile.add(menuItemExit);

        mbarMain.add(menuFile);

        menuEdit.setText("Edit");
        mbarMain.add(menuEdit);

        setJMenuBar(mbarMain);

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(tbStatusBar, javax.swing.GroupLayout.Alignment.TRAILING, javax.swing.GroupLayout.PREFERRED_SIZE, 0, Short.MAX_VALUE)
                    .addComponent(tabpaneMain)
                    .addComponent(spLog, javax.swing.GroupLayout.Alignment.TRAILING))
                .addContainerGap())
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, layout.createSequentialGroup()
                .addContainerGap()
                .addComponent(tabpaneMain, javax.swing.GroupLayout.PREFERRED_SIZE, 148, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(spLog, javax.swing.GroupLayout.DEFAULT_SIZE, 272, Short.MAX_VALUE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(tbStatusBar, javax.swing.GroupLayout.PREFERRED_SIZE, 25, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addContainerGap())
        );

        pack();
        setLocationRelativeTo(null);
    }// </editor-fold>//GEN-END:initComponents

    private void menuItemExitActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_menuItemExitActionPerformed
      System.exit(0);
    }//GEN-LAST:event_menuItemExitActionPerformed

    private void btnScanActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnScanActionPerformed
      alldevs.clear(); //Clear the ArrayList first
      int r = Pcap.findAllDevs(alldevs, errbuf);
      if (r == Pcap.NOT_OK || alldevs.isEmpty()) {
        appendLog(txtaLog, "Can't read list of devices, error is " + errbuf.toString() + "\n", Color.RED);
        return;
      }

      appendLog(txtaLog, "Network devices found:\n", Color.DARK_GRAY);
      cboxDevice.removeAllItems(); //Clear the ComboBox first
      int i = 1;
      for (PcapIf device : alldevs) {
        try {
          String description
              = (device.getDescription() != null) ? device.getDescription() : "No description available";
          appendLog(txtaLog, "    " + i++ + "." + device.getName() + " [" + description + "]"
              + " [" + asString(device.getHardwareAddress()) + "] " + "\n", Color.DARK_GRAY);
          cboxDevice.addItem(description + " - [" + asString(device.getHardwareAddress()) + "]");
        } catch (IOException e) {
          // Fail silently, device doesn't have a hardware address
        }
      }

      PcapIf device = alldevs.get(0); // We know we have at least 1 device  
      appendLog(txtaLog, "\nChoosing "
          + ((device.getDescription() != null) ? device.getDescription()
          : device.getName()) + " on your behalf.\n", Color.BLUE);
    }//GEN-LAST:event_btnScanActionPerformed

    private void tbtnCaptureActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_tbtnCaptureActionPerformed
      
      this.userVal = Integer.parseInt(spinPacketNumber.getValue().toString());
      this.numPackets = (userVal == 0) ? Pcap.LOOP_INFINITE : userVal;
      JTextPane[] packetPanes = {txtTotal,txtIncoming,txtISyn, txtISynAck, txtIFin, txtOutgoing, txtOSyn, txtOSynAck, txtRST, txtOFin, p1, p2, p3};
      this.tPCAP = new PacketCapture(userVal, numPackets, tbtnCapture, txtaLog, pcap, cboxDevice, alldevs, errbuf, packetPanes);
      Thread pcapThread = new Thread(tPCAP);
      pcapThread.start();
    }//GEN-LAST:event_tbtnCaptureActionPerformed

    private void tbtnCaptureStateChanged(javax.swing.event.ChangeEvent evt) {//GEN-FIRST:event_tbtnCaptureStateChanged
      tbtnCapture.setText((tbtnCapture.isSelected() ? "Packet Capture ON" : "Packet Capture OFF"));
      lblStatus.setText((tbtnCapture.isSelected() ? "Capturing Packets..." : "Ready"));
      lblStatus.setForeground((tbtnCapture.isSelected() ? new Color(150, 100, 0) : new Color(0, 150, 0)));
      pbarProgress.setVisible(tbtnCapture.isSelected());
      pbarProgress.setIndeterminate(tbtnCapture.isSelected());
      if (tPCAP != null) {
        tPCAP.setCapturing(tbtnCapture.isSelected());
      }
    }//GEN-LAST:event_tbtnCaptureStateChanged

  private static String asString(final byte[] mac) {
    final StringBuilder buf = new StringBuilder();
    for (byte b : mac) {
      if (buf.length() != 0) {
        buf.append(':');
      }
      if (b >= 0 && b < 16) {
        buf.append('0');
      }
      buf.append(Integer.toHexString((b < 0) ? b + 256 : b).toUpperCase());
    }

    return buf.toString();
  }

  /**
   * @param args the command line arguments
   */
  public static void main(String args[]) {
    /* Set the Nimbus look and feel */
    //<editor-fold defaultstate="collapsed" desc=" Look and feel setting code (optional) ">
        /* If Nimbus (introduced in Java SE 6) is not available, stay with the default look and feel.
     * For details see http://download.oracle.com/javase/tutorial/uiswing/lookandfeel/plaf.html 
     */
    try {
      for (javax.swing.UIManager.LookAndFeelInfo info : javax.swing.UIManager.getInstalledLookAndFeels()) {
        if ("Nimbus".equals(info.getName())) {
          javax.swing.UIManager.setLookAndFeel(info.getClassName());
          break;

        }
      }
    } catch (ClassNotFoundException ex) {
      java.util.logging.Logger.getLogger(MainFrame.class
          .getName()).log(java.util.logging.Level.SEVERE, null, ex);
    } catch (InstantiationException ex) {
      java.util.logging.Logger.getLogger(MainFrame.class
          .getName()).log(java.util.logging.Level.SEVERE, null, ex);
    } catch (IllegalAccessException ex) {
      java.util.logging.Logger.getLogger(MainFrame.class
          .getName()).log(java.util.logging.Level.SEVERE, null, ex);
    } catch (javax.swing.UnsupportedLookAndFeelException ex) {
      java.util.logging.Logger.getLogger(MainFrame.class
          .getName()).log(java.util.logging.Level.SEVERE, null, ex);
    }
    //</editor-fold>

    /* Create and display the form */
    java.awt.EventQueue.invokeLater(new Runnable() {
      @Override
      public void run() {
        new MainFrame().setVisible(true);
      }
    });
  }

    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JButton btnScan;
    private javax.swing.JComboBox cboxDevice;
    private javax.swing.Box.Filler filler1;
    private javax.swing.Box.Filler filler2;
    private javax.swing.JTextPane finNormal;
    private javax.swing.JLabel jLabel1;
    private javax.swing.JLabel jLabel10;
    private javax.swing.JLabel jLabel11;
    private javax.swing.JLabel jLabel12;
    private javax.swing.JLabel jLabel13;
    private javax.swing.JLabel jLabel14;
    private javax.swing.JLabel jLabel15;
    private javax.swing.JLabel jLabel2;
    private javax.swing.JLabel jLabel3;
    private javax.swing.JLabel jLabel4;
    private javax.swing.JLabel jLabel5;
    private javax.swing.JLabel jLabel6;
    private javax.swing.JLabel jLabel7;
    private javax.swing.JLabel jLabel8;
    private javax.swing.JLabel jLabel9;
    private javax.swing.JScrollPane jScrollPane1;
    private javax.swing.JScrollPane jScrollPane10;
    private javax.swing.JScrollPane jScrollPane11;
    private javax.swing.JScrollPane jScrollPane12;
    private javax.swing.JScrollPane jScrollPane13;
    private javax.swing.JScrollPane jScrollPane14;
    private javax.swing.JScrollPane jScrollPane15;
    private javax.swing.JScrollPane jScrollPane2;
    private javax.swing.JScrollPane jScrollPane3;
    private javax.swing.JScrollPane jScrollPane4;
    private javax.swing.JScrollPane jScrollPane5;
    private javax.swing.JScrollPane jScrollPane6;
    private javax.swing.JScrollPane jScrollPane7;
    private javax.swing.JScrollPane jScrollPane8;
    private javax.swing.JScrollPane jScrollPane9;
    private javax.swing.JLabel lblDevice;
    private javax.swing.JLabel lblPacketNumber;
    private javax.swing.JLabel lblStatus;
    private javax.swing.JMenuBar mbarMain;
    private javax.swing.JMenu menuEdit;
    private javax.swing.JMenu menuFile;
    private javax.swing.JMenuItem menuItemExit;
    private javax.swing.JTextPane p1;
    private javax.swing.JTextPane p2;
    private javax.swing.JTextPane p3;
    private javax.swing.JPanel panelAnomaly;
    private javax.swing.JPanel panelCapturing;
    private javax.swing.JPanel panelFiltering;
    private javax.swing.JPanel panelPHA;
    private javax.swing.JProgressBar pbarProgress;
    private javax.swing.JScrollPane spLog;
    private javax.swing.JSpinner spinPacketNumber;
    private javax.swing.JTextPane synNormal;
    private javax.swing.JTabbedPane tabpaneMain;
    private javax.swing.JToolBar tbStatusBar;
    private javax.swing.JToggleButton tbtnCapture;
    private javax.swing.JTextPane txtIFin;
    private javax.swing.JTextPane txtISyn;
    private javax.swing.JTextPane txtISynAck;
    private javax.swing.JTextPane txtIncoming;
    private javax.swing.JTextPane txtOFin;
    private javax.swing.JTextPane txtOSyn;
    private javax.swing.JTextPane txtOSynAck;
    private javax.swing.JTextPane txtOutgoing;
    private javax.swing.JTextPane txtRST;
    private javax.swing.JTextPane txtTotal;
    private javax.swing.JTextPane txtaLog;
    // End of variables declaration//GEN-END:variables
}
