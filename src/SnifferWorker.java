/**
 *
 * @author ghis
 */
import java.awt.Cursor;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.List;
import javax.swing.JLabel;
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
import org.jnetpcap.protocol.tcpip.Http;
import org.jnetpcap.protocol.tcpip.Tcp;
import org.jnetpcap.protocol.tcpip.Udp;
import org.jnetpcap.protocol.vpn.L2TP;
import org.jnetpcap.protocol.wan.PPP;
import org.jnetpcap.protocol.application.Html;
import org.jnetpcap.protocol.application.WebImage;
import org.jnetpcap.protocol.voip.Rtp;
import org.jnetpcap.protocol.voip.Sdp;
import org.jnetpcap.protocol.voip.Sip;
import org.jnetpcap.protocol.lan.Ethernet;
import org.jnetpcap.protocol.lan.IEEE802dot1q;
import org.jnetpcap.protocol.lan.IEEE802dot2;
import org.jnetpcap.protocol.lan.IEEE802dot3;
import org.jnetpcap.protocol.lan.IEEESnap;
import org.jnetpcap.protocol.lan.SLL;

 
public class SnifferWorker extends SwingWorker<Integer, Object[]> {
    DefaultTableModel packageTableModel;
    DefaultTableModel packages;
    JLabel packagesLabel;
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
        this.packages = new DefaultTableModel(new Object[][]{}, new String []{"Content", "Headers"});
        this.packagesLabel = gui.getPackagesLabel();
  
        //.setModel(new DefaultTableModel() }));
    }
    
    public void selectDevice(int index){
        
        packagesLabel.setText("Sniffed Packages (0)");
      
        String[] names = new String[]{
            "N°", 
            "Timestamp",
            "Protocol Headers",
            "Sender IP",
            "Target IP",
            "Sender MAC",
            "Target MAC",
            "Size", 
            "Content",
            "Headers"
        };     
        this.alldevs = gui.getAllDevs();
        gui.getStatusLabel().setText("Sniffing packages from "+((PcapIf)(alldevs.get(index))).getName()+" interface...");
        this.packageTableModel = new javax.swing.table.DefaultTableModel(
            new Object [][] {},
            names
        ) { };
        
        gui.getPackageList().setModel(packageTableModel);  
        StringBuilder errbuf = new StringBuilder();

        PcapIf device = (PcapIf) alldevs.get(index);

        int i = 1;
        int snaplen = 64 * 1024;           // Capture all packets, no trucation
        int flags = Pcap.MODE_PROMISCUOUS; // capture all packets
        int timeout = 10 * 1000;           // 10 seconds in millis

        System.out.println("Device "+index+" opened...");
        this.pcap = Pcap.openLive(device.getName(), snaplen, flags, timeout, errbuf);
        if (pcap == null) {
            System.err.printf("Error while opening device for capture: "
                    + errbuf.toString());
        }
        
    }
    
    @Override
    protected void done(){
        if(pcap != null){
            System.out.println("..breaking Loop");
            pcap.breakloop();
            System.out.println("..closing pcap");
            pcap.close();
        }
    }

    @Override
    protected Integer doInBackground() {
        
        //Create packet handler which will receive packets
        PcapPacketHandler jpacketHandler = new PcapPacketHandler() {
            Arp arp = new Arp();
            Icmp icmp = new Icmp();
            Ip4 ip4 = new Ip4();
            Ip6 ip6 = new Ip6();
            //Rip1 rip1 = new Rip1();
            Http http = new Http();
            Tcp tcp = new Tcp();
            Udp udp = new Udp();
            L2TP l2tp = new L2TP();
            PPP ppp = new PPP();
            Html html = new Html();
            WebImage webimage = new WebImage();
            Rtp rtp = new Rtp();
            Sdp sdp = new Sdp();
            Sip sip = new Sip();
            Ethernet eth = new Ethernet();
            IEEE802dot1q ieee = new IEEE802dot1q();
            IEEE802dot2 ieee2 = new IEEE802dot2();
            IEEE802dot3 ieee3 = new IEEE802dot3();
            IEEESnap ieees = new IEEESnap();
            SLL sll = new SLL();
            int count = 0;
            
            public String ip4ToString(byte[] _bytes){
                String file_string = "";
                for(int i = 0; i < _bytes.length; i++)
                    file_string += (_bytes[i] & 0xFF) + (i < _bytes.length-1 ? "." : "");
                return file_string;    
            }
            
            public String macToString(byte[] _bytes){
                final char[] hexArray = {'0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F'};
                char[] hexChars = new char[_bytes.length * 3 -1];
                int v;
                for ( int j = 0; j < _bytes.length; j++ ) {
                    v = _bytes[j] & 0xFF;
                    hexChars[j * 3] = hexArray[v >>> 4];
                    hexChars[j * 3 + 1] = hexArray[v & 0x0F];
                    if (j < _bytes.length-1)
                        hexChars[j * 3 + 2] = ':';
                }
                return new String(hexChars); 
            }

            public  String ip6ToString(byte[] _bytes) {
                StringBuilder retval = new StringBuilder(17);

                int i = 0;
                for (byte b : _bytes) {
                  retval.append(String.format("%02x", b & 0xff));
                  i++;
                  if (i%2==0 & i < _bytes.length) {
                    retval.append(":");
                  } 
                }
                return retval.toString();
            }
            
            @Override
            public void nextPacket(PcapPacket packet, Object t) {

                String  headers = "",
                        size = "",
                        frame = "",
                        hexa = "",
                        timestamp = "",
                        protocols = "",
                        ipSource = "",
                        macSource = "",
                        ipDestination = "",
                        macDestination = "";
                try {
                    frame = ""+packet.getFrameNumber();
                    size = packet.getTotalSize()+" bytes";
                    timestamp = new SimpleDateFormat("HH:mm:ss:SSS")
                       .format(new Date(packet.getCaptureHeader().timestampInMillis()));
                    protocols = 
                        (packet.hasHeader(arp) ? "Arp " : "")+
                        (packet.hasHeader(icmp) ? "Icmp " : "")+
                        (packet.hasHeader(ip4) ? "Ip4 " : "")+
                        (packet.hasHeader(ip6) ? "Ip6 " : "")+
                        //(packet.hasHeader(rip1) ? "Rip1 " : "")+
                        (packet.hasHeader(http) ? "Http " : "")+
                        (packet.hasHeader(tcp) ? "Tcp " : "")+
                        (packet.hasHeader(udp) ? "Udp " : "")+
                        (packet.hasHeader(l2tp) ? "L2TP " : "")+
                        (packet.hasHeader(ppp) ? "PPP " : "")+
                        (packet.hasHeader(html) ? "Html " : "")+
                        (packet.hasHeader(webimage) ? "WebImage " : "")+
                        (packet.hasHeader(rtp) ? "Rtp " : "")+
                        (packet.hasHeader(sdp) ? "Sdp " : "")+
                        (packet.hasHeader(sip) ? "Sip " : "")+
                        (packet.hasHeader(eth) ? "Ethernet " : "")+
                        (packet.hasHeader(ieee) ? "IEEE802dot1q " : "")+
                        (packet.hasHeader(ieee2) ? "IEEE802dot2 " : "")+
                        (packet.hasHeader(ieee3) ? "IEEE802dot3 " : "")+
                        (packet.hasHeader(ieees) ? "IEEESnap " : "")+
                        (packet.hasHeader(sll) ? "SLL " : "");
                    hexa = packet.toHexdump();
                    headers = "<h1>Frame</h1><table>"+
                    packet.toString()
                        .replaceAll("\n([^:\n]*):[ ]*[*]{6,}[ ]*([^\n]*)", "</table><h1>$2</h1>")
                        .replaceAll("<h1>([^<]*)-?[ ]*(offset[^<]*)</h1>", "<h1>$1<small>$2</small></h1>")
                        .replaceAll("Data:[ ]*\n", "<pre style=\"background: #000000; color: #FFFFFF; padding: 5px;\">")
                        .replaceAll("([^:\n]*):[ ]*\n", "<table>")
                        .replaceAll("([^:\n ]*):[ ]+([^=\n<>]+)=([^\n<>]+)\n", "<tr><th align=\"right\">$2</th><td>$3</td></tr>\n")
                        .replaceAll("[^:\n]*:[\n ]*</table>", "</table>")
                    +"</pre>";
                    ipSource =  
                          packet.hasHeader(ip4) ?
                        ip4ToString(ip4.source())
                        : packet.hasHeader(ip6) ?
                        ip6ToString(ip6.source())
                        : packet.hasHeader(arp) ?
                        ip4ToString(arp.spa())
                        : "";
                    ipDestination = 
                          packet.hasHeader(ip4) ?
                        ip4ToString(ip4.destination())
                        : packet.hasHeader(ip6) ?
                        ip6ToString(ip6.destination())
                        : packet.hasHeader(arp) ?
                        ip4ToString(arp.tpa())
                        : "";
                    macSource = 
                          packet.hasHeader(eth) ?
                        macToString(eth.source())
                        : packet.hasHeader(arp) ?
                        macToString(arp.sha())
                        : "";
                    macDestination = 
                          packet.hasHeader(eth) ?
                        macToString(eth.destination())
                        : packet.hasHeader(arp) ?
                        macToString(arp.tha())
                        : "";
                    
                } catch(Exception e) {
                    headers = "<pre>"+e.getMessage()+"</pre>";
                }
                
                publish(new Object []{
                    frame,
                    timestamp,
                    protocols,
                    ipSource,
                    ipDestination,
                    macSource,
                    macDestination,
                    size,
                    hexa,
                    headers
                    /*
                    "Header |"+packet.getCaptureHeader().toDebugString().replace("\n", "\n       |")+"\n\n"+
                    "State  |"+packet.getState().toDebugString().replace("\n", "\n       |")+"\n\n"+
                    "Packet |"+packet.toDebugString().replace("\n", "\n       |")+"\n\n"+
                    (packet.hasHeader(arp)      ? "Arp    |"+arp.toDebugString().replace("\n", "\n       |")+"\n\n":"")+
                    (packet.hasHeader(icmp)     ? "Icmp   |"+icmp.toDebugString().replace("\n", "\n       |")+"\n\n":"")+
                    (packet.hasHeader(ip4)      ? 
                        "Ip4    | ["+ip4.getDescription()+"] Size: "+ip4.size()+" bytes - Offset: "+ip4.offset()+"\n"+
                        //ip4.toDebugString().replace("\n", "\n       |")+  
                        "       | Content: "+ip4.toString()+
                        "-------|---------------------------------------------------\n"+
                        ip4.toHexdump().replaceAll("(.{4}): ", "       | $1:")+
                        "\n\n":"")+
                    (packet.hasHeader(ip6)      ? "Ip6    |"+ip6.toDebugString().replace("\n", "\n       |")+"\n\n":"")+
                    //(packet.hasHeader(rip1)   ? "Rip1|"+ip4.toDebugString().replace("\n", "\n       |"):"")+
                    (packet.hasHeader(http)     ? "Http   |"+http.toDebugString().replace("\n", "\n       |")+"\n\n":"")+
                    (packet.hasHeader(tcp)      ? "Tcp    |"+tcp.toDebugString().replace("\n", "\n       |")+"\n\n":"")+
                    (packet.hasHeader(udp)      ? "Udp    |"+udp.toDebugString().replace("\n", "\n       |")+"\n\n":"")+
                    (packet.hasHeader(l2tp)     ? "L2TP   |"+l2tp.toDebugString().replace("\n", "\n       |")+"\n\n":"")+
                    (packet.hasHeader(ppp)      ? "PPP    |"+ppp.toDebugString().replace("\n", "\n       |")+"\n\n":"")+
                    (packet.hasHeader(html)     ? "Html   |"+html.toDebugString().replace("\n", "\n       |")+"\n\n":"")+
                    (packet.hasHeader(webimage) ? "WebImg |"+webimage.toDebugString().replace("\n", "\n       |")+"\n\n":"")+
                    (packet.hasHeader(rtp)      ? "Rtp    |"+rtp.toDebugString().replace("\n", "\n       |")+"\n\n":"")+
                    (packet.hasHeader(sdp)      ? "Sdp    |"+sdp.toDebugString().replace("\n", "\n       |")+"\n\n":"")+
                    (packet.hasHeader(sip)      ? "Sip    |"+sip.toDebugString().replace("\n", "\n       |")+"\n\n":"")+
                    (packet.hasHeader(eth)      ? "Ethrnt |"+eth.toDebugString().replace("\n", "\n       |")+"\n\n":"")+
                    (packet.hasHeader(ieee)     ? "IEEE1q |"+ieee.toDebugString().replace("\n", "\n       |")+"\n\n":"")+
                    (packet.hasHeader(ieee2)    ? "IEEE2  |"+ieee2.toDebugString().replace("\n", "\n       |")+"\n\n":"")+
                    (packet.hasHeader(ieee3)    ? "IEEE3  |"+ieee3.toDebugString().replace("\n", "\n       |")+"\n\n":"")+
                    (packet.hasHeader(ieees)    ? "IEEESnp|"+ieees.toDebugString().replace("\n", "\n       |")+"\n\n":"")+
                    (packet.hasHeader(sll)      ? "SLL    |"+sll.toDebugString().replace("\n", "\n       |"):"")*/
                });

            }
        };
        
        System.out.println("Sniffing...");
        pcap.loop(Pcap.LOOP_INFINITE, jpacketHandler, "jnetpcap rocks!");
        System.out.println("Finished.");
        //Close th  pcap
  
        //pcap.close();
        
        return 1;
    }
    
  @Override
  protected void process(List<Object []> pkgs){
    for(Object [] pkg : pkgs){
      packageTableModel.addRow(pkg);
      packagesLabel.setText("Sniffed Packages ("+packageTableModel.getRowCount()+")");
    }
  }

}