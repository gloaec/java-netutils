/**
 *
 * @author ghis
 */
import java.awt.Cursor;
import java.io.UnsupportedEncodingException;
import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;
import java.util.concurrent.ExecutionException;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.swing.JFrame;
import javax.swing.SwingWorker;
import javax.swing.table.DefaultTableModel;
import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;
import org.jnetpcap.protocol.network.Arp;
import org.jnetpcap.protocol.network.Icmp;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.network.Ip6;
import org.jnetpcap.protocol.network.Rip;

 
public class SnifferWorker extends SwingWorker<Integer, Integer> {
    DefaultTableModel packageTableModel;
    int deviceIndex;
    List alldevs;
    Pcap pcap;
    
    /**
     * The frame which must have the default cursor set 
     * at the end of the background task
     */
    private MainFrame gui;

    public SnifferWorker(MainFrame gui) {
        //super();
        this.gui = gui;
        this.deviceIndex = gui.getInterfaceList().getSelectedIndex();
        this.alldevs = gui.getAllDevs();
        String[] names = new String[]{"Type","Description", "Destination","Size", "HardwareType", "Protocol","Content"};
        gui.getPackageList().setModel(new javax.swing.table.DefaultTableModel(
            new Object [][] {},
            names
        ) { });//.setModel(new DefaultTableModel() }));
        System.out.println("device "+deviceIndex+" opened");
        gui.getStatusLabel().setText("Sniffing packages from interface "+deviceIndex);
        this.packageTableModel = (DefaultTableModel)gui.getPackageList().getModel();
        StringBuilder errbuf = new StringBuilder();

        PcapIf device = (PcapIf) alldevs.get(this.deviceIndex);

        int i = 1;
        int snaplen = 64 * 1024;           // Capture all packets, no trucation
        int flags = Pcap.MODE_PROMISCUOUS; // capture all packets
        int timeout = 10 * 1000;           // 10 seconds in millis

        //Open the selected device to capture packets
        this.pcap = Pcap.openLive(device.getName(), snaplen, flags, timeout, errbuf);

        if (pcap == null) {
            System.err.printf("Error while opening device for capture: "
                    + errbuf.toString());
        }

    }

    @Override
    protected void done() {
        // the done method is called in the EDT. 
        // No need for SwingUtilities.invokeLater here

        gui.setCursor(Cursor.getPredefinedCursor(Cursor.DEFAULT_CURSOR));
    }
    
    public void close(){ pcap.breakloop(); pcap.close(); }

    @Override
    protected Integer doInBackground() {

        //Create packet handler which will receive packets
        PcapPacketHandler jpacketHandler = new PcapPacketHandler() {
            Arp arp = new Arp();
            Icmp icmp = new Icmp();
            Ip4 ip4 = new Ip4();
            Ip6 ip6 = new Ip6();
            int count = 0;
       
            @Override
            public void nextPacket(PcapPacket packet, Object t) {
                if (packet.hasHeader(arp)) {
                    packageTableModel.addRow(new Object []{
                        "ARP", 
                        arp.getDescription(),
                        packet.getTotalSize(), 
                        arp.hardwareType(), 
                        arp.protocolType(), 
                        arp.getPacket()
                    });
                    System.out.println("Packet Arp");
                    publish(count++);
                } else
                if (packet.hasHeader(icmp)) {
                    packageTableModel.addRow(new Object []{
                        "IMPC", 
                        icmp.getDescription(),
                        packet.getTotalSize(),
                        "", 
                        "", 
                        icmp.getPacket()
                    });
                    System.out.println("Packet Imcp");
                    publish(count++);
                } else
                if (packet.hasHeader(ip4)) {
                    try {
                        packageTableModel.addRow(new Object []{
                            "IP4",
                            ip4.getDescription(),
                            new String( ip4.destination(), "UTF-8" ),
                            packet.getTotalSize(), 
                            ip4.getPacket().getTotalSize(), 
                            ip4.getPacket()
                        });
                    } catch (UnsupportedEncodingException ex) {
                        Logger.getLogger(SnifferWorker.class.getName()).log(Level.SEVERE, null, ex);
                    }
  
                    System.out.println("Packet Ip4");
                    publish(count++);
                } else
                if (packet.hasHeader(ip6)) {
                    packageTableModel.addRow(new Object []{
                        "IP6", 
                        ip6.getDescription(),
                        packet.getTotalSize(), 
                        "", 
                        "", 
                        ip6.getPacket()
                    });
                    System.out.println("Packet Ip6");
                    publish(count++);
                } 
            }
        };
        //we enter the loop and capture the 10 packets here.You can  capture any number of packets just by changing the first argument to pcap.loop() function below
        pcap.loop(-1, jpacketHandler, "jnetpcap rocks!");
        //Close th  pcap
        
        return 1;
    }
}