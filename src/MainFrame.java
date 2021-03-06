import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;
import java.net.*;
import javax.swing.DefaultListModel;
import javax.swing.JFrame;
import javax.swing.ListModel;
import javax.swing.SwingUtilities;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableModel;
import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;
import org.jnetpcap.protocol.network.Arp;
import javax.swing.text.html.HTMLEditorKit;
/*
 * MainFrame.java
 *
 * Created on May 15, 2013, 6:30:51 PM
 */
/**
 *
 * @author root
 */
public class MainFrame extends javax.swing.JFrame {

    /** Creates new form MainFrame */
    public MainFrame() {
        initComponents();
        initSniffer();
    }

    /** This method is called from within the constructor to
     * initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is
     * always regenerated by the Form Editor.
     */
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        jTabbedPane1 = new javax.swing.JTabbedPane();
        jPanel2 = new javax.swing.JPanel();
        jSplitPane1 = new javax.swing.JSplitPane();
        jPanel3 = new javax.swing.JPanel();
        jSplitPane2 = new javax.swing.JSplitPane();
        jPanel1 = new javax.swing.JPanel();
        interfaceLabel = new javax.swing.JLabel();
        jScrollPane2 = new javax.swing.JScrollPane();
        interfaceList = new javax.swing.JList();
        jPanel5 = new javax.swing.JPanel();
        jScrollPane1 = new javax.swing.JScrollPane();
        packageList = new javax.swing.JTable();
        packagesLabel = new javax.swing.JLabel();
        searchButton = new javax.swing.JButton();
        searchField = new javax.swing.JTextField();
        jPanel4 = new javax.swing.JPanel();
        jScrollPane3 = new javax.swing.JScrollPane();
        packagePreview = new javax.swing.JTextArea();
        jLabel3 = new javax.swing.JLabel();
        statusLabel = new javax.swing.JLabel();
        jLabel1 = new javax.swing.JLabel();
        jScrollPane4 = new javax.swing.JScrollPane();
        headersView = new javax.swing.JEditorPane();

        setDefaultCloseOperation(javax.swing.WindowConstants.EXIT_ON_CLOSE);
        setTitle("java-netutils");

        jTabbedPane1.addFocusListener(new java.awt.event.FocusAdapter() {
            public void focusGained(java.awt.event.FocusEvent evt) {
                jTabbedPane1FocusGained(evt);
            }
        });

        org.jdesktop.layout.GroupLayout jPanel2Layout = new org.jdesktop.layout.GroupLayout(jPanel2);
        jPanel2.setLayout(jPanel2Layout);
        jPanel2Layout.setHorizontalGroup(
            jPanel2Layout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
            .add(0, 814, Short.MAX_VALUE)
        );
        jPanel2Layout.setVerticalGroup(
            jPanel2Layout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
            .add(0, 421, Short.MAX_VALUE)
        );

        jTabbedPane1.addTab("Network Scanner", jPanel2);

        jSplitPane1.setDividerLocation(200);
        jSplitPane1.setOrientation(javax.swing.JSplitPane.VERTICAL_SPLIT);

        interfaceLabel.setText("Choose an interface");

        interfaceList.addListSelectionListener(new javax.swing.event.ListSelectionListener() {
            public void valueChanged(javax.swing.event.ListSelectionEvent evt) {
                interfaceListValueChanged(evt);
            }
        });
        interfaceList.addComponentListener(new java.awt.event.ComponentAdapter() {
            public void componentShown(java.awt.event.ComponentEvent evt) {
                interfaceListComponentShown(evt);
            }
        });
        jScrollPane2.setViewportView(interfaceList);

        org.jdesktop.layout.GroupLayout jPanel1Layout = new org.jdesktop.layout.GroupLayout(jPanel1);
        jPanel1.setLayout(jPanel1Layout);
        jPanel1Layout.setHorizontalGroup(
            jPanel1Layout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
            .add(jPanel1Layout.createSequentialGroup()
                .addContainerGap()
                .add(interfaceLabel)
                .addContainerGap(33, Short.MAX_VALUE))
            .add(jScrollPane2, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, 188, Short.MAX_VALUE)
        );
        jPanel1Layout.setVerticalGroup(
            jPanel1Layout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
            .add(jPanel1Layout.createSequentialGroup()
                .add(18, 18, 18)
                .add(interfaceLabel)
                .add(18, 18, 18)
                .add(jScrollPane2, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, 146, Short.MAX_VALUE))
        );

        jSplitPane2.setLeftComponent(jPanel1);

        packageList.setModel(new javax.swing.table.DefaultTableModel(
            new Object [][] {

            },
            new String [] {
                "Type", "Hardware", "Protocol"
            }
        ) {
            Class[] types = new Class [] {
                java.lang.String.class, java.lang.String.class, java.lang.String.class
            };
            boolean[] canEdit = new boolean [] {
                false, false, false
            };

            public Class getColumnClass(int columnIndex) {
                return types [columnIndex];
            }

            public boolean isCellEditable(int rowIndex, int columnIndex) {
                return canEdit [columnIndex];
            }
        });
        packageList.addMouseListener(new java.awt.event.MouseAdapter() {
            public void mouseClicked(java.awt.event.MouseEvent evt) {
                packageListMouseClicked(evt);
            }
        });
        jScrollPane1.setViewportView(packageList);

        packagesLabel.setText("Sniffed Packages (0)");

        searchButton.setText("Filter");
        searchButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                searchButtonActionPerformed(evt);
            }
        });

        searchField.addKeyListener(new java.awt.event.KeyAdapter() {
            public void keyPressed(java.awt.event.KeyEvent evt) {
                searchFieldKeyPressed(evt);
            }
        });

        org.jdesktop.layout.GroupLayout jPanel5Layout = new org.jdesktop.layout.GroupLayout(jPanel5);
        jPanel5.setLayout(jPanel5Layout);
        jPanel5Layout.setHorizontalGroup(
            jPanel5Layout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
            .add(jScrollPane1, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, 612, Short.MAX_VALUE)
            .add(jPanel5Layout.createSequentialGroup()
                .addContainerGap()
                .add(packagesLabel)
                .addPreferredGap(org.jdesktop.layout.LayoutStyle.RELATED, 127, Short.MAX_VALUE)
                .add(searchField, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE, 217, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(org.jdesktop.layout.LayoutStyle.RELATED)
                .add(searchButton, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE, 94, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE)
                .addContainerGap())
        );
        jPanel5Layout.setVerticalGroup(
            jPanel5Layout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
            .add(jPanel5Layout.createSequentialGroup()
                .add(12, 12, 12)
                .add(jPanel5Layout.createParallelGroup(org.jdesktop.layout.GroupLayout.BASELINE)
                    .add(packagesLabel)
                    .add(searchField, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE, 27, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE)
                    .add(searchButton))
                .addPreferredGap(org.jdesktop.layout.LayoutStyle.UNRELATED)
                .add(jScrollPane1, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, 146, Short.MAX_VALUE))
        );

        jSplitPane2.setRightComponent(jPanel5);

        org.jdesktop.layout.GroupLayout jPanel3Layout = new org.jdesktop.layout.GroupLayout(jPanel3);
        jPanel3.setLayout(jPanel3Layout);
        jPanel3Layout.setHorizontalGroup(
            jPanel3Layout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
            .add(jSplitPane2, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, 812, Short.MAX_VALUE)
        );
        jPanel3Layout.setVerticalGroup(
            jPanel3Layout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
            .add(jSplitPane2, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, 199, Short.MAX_VALUE)
        );

        jSplitPane1.setLeftComponent(jPanel3);

        packagePreview.setColumns(20);
        packagePreview.setEditable(false);
        packagePreview.setFont(new java.awt.Font("Ubuntu Mono", 0, 14));
        packagePreview.setRows(5);
        jScrollPane3.setViewportView(packagePreview);

        jLabel3.setText("Package Contents");

        statusLabel.setFont(new java.awt.Font("Dialog", 0, 12));
        statusLabel.setText("Loading...");

        jLabel1.setText("Headers / Details");

        headersView.setContentType("text/html");
        headersView.setFont(new java.awt.Font("Ubuntu Mono", 0, 14));
        headersView.setForeground(new java.awt.Color(0, 0, 0));
        jScrollPane4.setViewportView(headersView);

        org.jdesktop.layout.GroupLayout jPanel4Layout = new org.jdesktop.layout.GroupLayout(jPanel4);
        jPanel4.setLayout(jPanel4Layout);
        jPanel4Layout.setHorizontalGroup(
            jPanel4Layout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
            .add(jPanel4Layout.createSequentialGroup()
                .add(jPanel4Layout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
                    .add(jPanel4Layout.createSequentialGroup()
                        .addContainerGap()
                        .add(statusLabel))
                    .add(jPanel4Layout.createSequentialGroup()
                        .addContainerGap()
                        .add(jLabel3))
                    .add(jScrollPane3, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE, 567, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE))
                .addPreferredGap(org.jdesktop.layout.LayoutStyle.RELATED)
                .add(jPanel4Layout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
                    .add(jPanel4Layout.createSequentialGroup()
                        .add(jLabel1)
                        .addContainerGap(111, Short.MAX_VALUE))
                    .add(jScrollPane4, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, 233, Short.MAX_VALUE)))
        );
        jPanel4Layout.setVerticalGroup(
            jPanel4Layout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
            .add(org.jdesktop.layout.GroupLayout.TRAILING, jPanel4Layout.createSequentialGroup()
                .add(18, 18, 18)
                .add(jPanel4Layout.createParallelGroup(org.jdesktop.layout.GroupLayout.BASELINE)
                    .add(jLabel3)
                    .add(jLabel1))
                .add(18, 18, 18)
                .add(jPanel4Layout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
                    .add(jScrollPane4, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, 138, Short.MAX_VALUE)
                    .add(jScrollPane3, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, 138, Short.MAX_VALUE))
                .addPreferredGap(org.jdesktop.layout.LayoutStyle.RELATED)
                .add(statusLabel))
        );

        jSplitPane1.setRightComponent(jPanel4);

        jTabbedPane1.addTab("Package Sniffer", jSplitPane1);

        org.jdesktop.layout.GroupLayout layout = new org.jdesktop.layout.GroupLayout(getContentPane());
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
            .add(jTabbedPane1, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, 819, Short.MAX_VALUE)
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
            .add(layout.createSequentialGroup()
                .add(jTabbedPane1, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, 448, Short.MAX_VALUE)
                .addContainerGap())
        );

        pack();
    }// </editor-fold>//GEN-END:initComponents

private void jTabbedPane1FocusGained(java.awt.event.FocusEvent evt) {//GEN-FIRST:event_jTabbedPane1FocusGained
   
}//GEN-LAST:event_jTabbedPane1FocusGained

private void initSniffer(){
    alldevs = new ArrayList();
    // For any error msgs
    errbuf = new StringBuilder();

    //Getting a list of devices
    int r = Pcap.findAllDevs(alldevs, errbuf);
    if (r != Pcap.OK) {
        statusLabel.setText("Can't read list of devices, error is " + errbuf.toString());
        return;
    }

    interfaceLabel.setText("Network devices ("+alldevs.size()+")");
    interfaceList.setModel(new DefaultListModel());
    
    int i = 0;
    for (Object obj : alldevs) {
        PcapIf device = (PcapIf) obj;
        String description =
                (device.getDescription() != null) ? device.getDescription()
                : "No description available";
        DefaultListModel interfaceListModel = (DefaultListModel)interfaceList.getModel();
        interfaceListModel.addElement(device.getName()+" ["+description+"]");
    } 
    
    snifferWorker = new SnifferWorker(this);
}

private void interfaceListComponentShown(java.awt.event.ComponentEvent evt) {//GEN-FIRST:event_interfaceListComponentShown
    statusLabel.setText("Working");
}//GEN-LAST:event_interfaceListComponentShown

private void interfaceListValueChanged(javax.swing.event.ListSelectionEvent evt) {//GEN-FIRST:event_interfaceListValueChanged
    if(interfaceSelected != interfaceList.getSelectedIndex()){
        snifferWorker.cancel(true);
        interfaceSelected = interfaceList.getSelectedIndex();
        snifferWorker = new SnifferWorker(this);
        snifferWorker.selectDevice(interfaceSelected);
        snifferWorker.execute();
    }
}//GEN-LAST:event_interfaceListValueChanged

private void packageListMouseClicked(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_packageListMouseClicked
       
    int row = packageList.getSelectedRow();
    DefaultTableModel tableModel = (DefaultTableModel) packageList.getModel();

    String content = tableModel.getValueAt(row, 8).toString();
    String headers = tableModel.getValueAt(row, 9).toString();
    packagePreview.setText(content);
    headersView.setText(headers);
}//GEN-LAST:event_packageListMouseClicked

private void searchButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_searchButtonActionPerformed
    search();
}//GEN-LAST:event_searchButtonActionPerformed

private void searchFieldKeyPressed(java.awt.event.KeyEvent evt) {//GEN-FIRST:event_searchFieldKeyPressed
                                  
    if(evt.getKeyCode() == 10) // ENTER
        search();
}//GEN-LAST:event_searchFieldKeyPressed

private void search(){    
    String text = searchField.getText();
    if( "".equals(text)){ 
        searchMode = false;
        packageList.setModel(packages);
    } else {
        if(!searchMode){
          packages = packageList.getModel();
          searchMode = true;
        }
        String[] names = new String[]{
            "N°", 
            "Timestamp",
            "Protocol Headers",
            "Sender IP",
            "Target IP",
            "Sender MAC",
            "Target MAC",
            "Size", 
           /* "Operation",
            "ProtocolType",
            "HardwareType",*/
            "Content",
            "Headers"
        };
        DefaultTableModel searchResults = new DefaultTableModel(
            new Object [][]{}, 
            names
        );
        System.out.print("SEARCH => '"+text+"' [");
       
        packageList.setModel(searchResults);
        for(int i=0; i<packages.getRowCount(); i++){ 
            boolean match = false;
            String [] row = new String[10];
            for(int j=0; j<packages.getColumnCount(); j++){
                String cell = packages.getValueAt(i, j).toString();
                match = match || cell.matches(".*"+text+".*");
                row[j] = cell;
            }
            if(match){
                //System.out.println("ROW: "+row.toString());
                searchResults.addRow(row);
            }
            System.out.print(match ? "Y":"n");
        }
        System.out.println("]");
    }
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
            java.util.logging.Logger.getLogger(MainFrame.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (InstantiationException ex) {
            java.util.logging.Logger.getLogger(MainFrame.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (IllegalAccessException ex) {
            java.util.logging.Logger.getLogger(MainFrame.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (javax.swing.UnsupportedLookAndFeelException ex) {
            java.util.logging.Logger.getLogger(MainFrame.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        }
        
        
        //</editor-fold>

        /* Create and display the form */
        java.awt.EventQueue.invokeLater(new Runnable() {           
            public void run() {
                
                MainFrame myFrame = new MainFrame();
                myFrame.setVisible(true);
                //myFrame.setExtendedState(myFrame.getExtendedState() | JFrame.MAXIMIZED_BOTH);
                
            }
        });
    }
    private int interfaceSelected = -1;
    private List alldevs;
    private boolean searchMode = false;
    private StringBuilder errbuf;
    private SnifferWorker snifferWorker;
    private TableModel packages;
    public javax.swing.JLabel getStatusLabel() { return statusLabel; }
    public javax.swing.JList getInterfaceList(){ return this.interfaceList; }
    public javax.swing.JTable getPackageList(){ return this.packageList; }
    public javax.swing.JLabel getPackagesLabel(){ return this.packagesLabel; }
    public javax.swing.JTextArea getPackagePreview(){ return this.packagePreview; }
    public javax.swing.JEditorPane getHeadersView(){ return this.headersView; }
    public List getAllDevs(){ return this.alldevs; }
    public StringBuilder getErrorBuf(){ return this.errbuf; }
    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JEditorPane headersView;
    private javax.swing.JLabel interfaceLabel;
    private javax.swing.JList interfaceList;
    private javax.swing.JLabel jLabel1;
    private javax.swing.JLabel jLabel3;
    private javax.swing.JPanel jPanel1;
    private javax.swing.JPanel jPanel2;
    private javax.swing.JPanel jPanel3;
    private javax.swing.JPanel jPanel4;
    private javax.swing.JPanel jPanel5;
    private javax.swing.JScrollPane jScrollPane1;
    private javax.swing.JScrollPane jScrollPane2;
    private javax.swing.JScrollPane jScrollPane3;
    private javax.swing.JScrollPane jScrollPane4;
    private javax.swing.JSplitPane jSplitPane1;
    private javax.swing.JSplitPane jSplitPane2;
    private javax.swing.JTabbedPane jTabbedPane1;
    private javax.swing.JTable packageList;
    private javax.swing.JTextArea packagePreview;
    private javax.swing.JLabel packagesLabel;
    private javax.swing.JButton searchButton;
    private javax.swing.JTextField searchField;
    private javax.swing.JLabel statusLabel;
    // End of variables declaration//GEN-END:variables
}
