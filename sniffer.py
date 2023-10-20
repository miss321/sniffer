from PyQt5.QtWidgets import QApplication, QMainWindow, QTextEdit, QComboBox, QPushButton, QVBoxLayout, QWidget, \
    QTableWidget, QTableWidgetItem, QMessageBox
from PyQt5.QtCore import QThread, pyqtSignal, Qt
from scapy.arch.windows import get_windows_if_list
from scapy.all import *
import threading
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import Ether, ARP
from scapy.layers.dns import DNS

class PacketSnifferWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Sniffer")
        self.setGeometry(100, 100, 800, 600)
        self.setup_ui()
        self.packet_count = 0  # packet counter
        self.pcap_packets = []  # Used to save captured packets

    def setup_ui(self):
        # Create an interface selection drop-down menu
        self.interface_var = QComboBox(self)
        self.interface_var.move(10, 10)

        # Create protocol selection drop-down menu
        self.protocol_var  = QComboBox(self)
        self.protocol_var .move(200, 10)
        self.protocol_var .addItems(["All", "TCP", "UDP", "ICMP", "DNS"])
        self.protocol_var .setCurrentIndex(0)  # Default to select All protocols

        # Create Forms
        self.table_widget = QTableWidget(self)
        self.table_widget.setGeometry(10, 40, 780, 300)
        self.table_widget.setColumnCount(4)
        self.table_widget.setHorizontalHeaderLabels(["Protocol type", "Source IP", "destination IP", "Lengths"])
        self.table_widget.setSelectionBehavior(QTableWidget.SelectRows)
        self.table_widget.cellClicked.connect(self.show_packet_details)

        # Create Details Text Edit Boxes
        self.detail_text_edit = QTextEdit(self)
        self.detail_text_edit.setGeometry(10, 350, 780, 200)

        # Create Button
        self.start_button = QPushButton("Start", self)
        self.start_button.setGeometry(10, 560, 80, 30)
        self.start_button.clicked.connect(self.packet_sniffer)

        self.stop_button = QPushButton("Stop", self)
        self.stop_button.setGeometry(100, 560, 80, 30)
        self.stop_button.clicked.connect(self.stop_sniffing)
        self.stop_button.setEnabled(False)

        self.reset_button = QPushButton("Reset", self)
        self.reset_button.setGeometry(190, 560, 80, 30)
        self.reset_button.clicked.connect(self.reset_sniffer)

        self.export_button = QPushButton("Export", self)
        self.export_button.setGeometry(280, 560, 80, 30)
        self.export_button.clicked.connect(self.export_file)

        # Get a list of available network interface names
        interfaces = self.get_interface_names()

        # Add a list of interfaces to the drop-down menu
        self.interface_var.addItems(interfaces)
        self.interface_var.setCurrentIndex(0)  # The first interface is selected by default

    def get_interface_names(self):
        interfaces = []
        for iface in get_windows_if_list():
            interfaces.append(iface["name"])
        return interfaces

    def packet_sniffer(self):
        iface = self.interface_var.currentText()

        self.stop_sniffing_event = threading.Event()
        selected_protocol = self.protocol_var.currentText()  # Get user-selected protocols
        
        # Create Filter Criteria
        if selected_protocol == "All":
            filter_str = ""
        elif selected_protocol == "TCP":
            filter_str = "tcp"
        elif selected_protocol == "UDP":
            filter_str = "udp"
        elif selected_protocol == "ICMP":
            filter_str = "icmp"
        elif selected_protocol == "DNS":
            filter_str = "udp and port 53"

        def packet_handler(self, packet):
            pkt_summary = []
            ethernet = packet.getlayer(Ether)
            ip = packet.getlayer(IP)
            tcp = packet.getlayer(TCP)
            udp = packet.getlayer(UDP)
            icmp = packet.getlayer(ICMP)
            arp = packet.getlayer(ARP)
            dns = packet.getlayer(DNS)

            if ip:
                if tcp:
                    pkt_summary.append("TCP")
                elif udp:
                    if dns:
                        pkt_summary.append("DNS")
                    else:
                        pkt_summary.append("UDP")
                elif icmp:
                    pkt_summary.append("ICMP")
                else:
                    pkt_summary.append("IP")

                pkt_summary.append(ip.src)
                pkt_summary.append(ip.dst)
                pkt_summary.append(str(len(packet)))  # packet length
            elif arp:
                pkt_summary.extend(["ARP", arp.psrc, arp.pdst, "28"])  # ARP packet length is fixed at 28 bytes
            else:
                pkt_summary.extend(["IPv6", "-", "-", "-"])  # ipv6 packet

            self.packet_received.emit(pkt_summary, packet)

        def start_sniffing():
            try:
                sniff(iface=iface, prn=packet_handler, store=False,
                        stop_filter=lambda _: self.stop_sniffing_event.is_set(),
                        filter=filter_str)  # Start to filter
            except OSError as e:
                self.detail_text_edit.append("Error opening adapter: " + str(e))
        # Create and start a sniffing thread
        self.sniff_thread = SniffThread(iface, filter_str)
        self.sniff_thread.packet_received.connect(self.packet_received)
        self.sniff_thread.start()

        # Update the button state
        self.start_button.setEnabled(False)
        self.stop_button.setEnabled(True)

    def stop_sniffing(self):
        if self.sniff_thread and self.sniff_thread.isRunning():
            self.stop_sniffing_event.set()
            self.sniff_thread.wait(2)
            if self.sniff_thread.isRunning():
                self.sniff_thread.terminate()
        self.start_button.setEnabled(True)

    def reset_sniffer(self):
        self.packet_count = 0
        self.table_widget.clearContents()
        self.table_widget.setRowCount(0)
        self.detail_text_edit.clear()
        self.pcap_packets = []

    def export_file(self):
        file_name = "file.pcap"
        wrpcap(file_name, self.pcap_packets)
        self.detail_text_edit.append("The file is exported successfully: " + file_name)

    def packet_received(self, pkt_summary, packet):
        self.packet_count += 1
        row_count = self.table_widget.rowCount()
        self.table_widget.setRowCount(row_count + 1)

        # Add packet information to the table
        for i, info in enumerate(pkt_summary):
            info_item = QTableWidgetItem(info)
            self.table_widget.setItem(row_count, i, info_item)

        # Save the original packet reference so that the details are displayed when the row is tapped
        self.table_widget.item(row_count, 0).setData(Qt.UserRole, packet)

        # Add the packet to the PCAP packet list
        self.pcap_packets.append(packet)

    def show_packet_details(self, row, column):
        packet = self.table_widget.item(row, 0).data(Qt.UserRole)
        if packet:
            self.detail_text_edit.clear()
            self.detail_text_edit.append("Hexdump:")
            hexdump_str = hexdump(packet, dump=True)
            self.detail_text_edit.append(hexdump_str)
            self.detail_text_edit.append("\nData summary:")
            self.detail_text_edit.append(packet.summary())

    # def open_packet_details(self):
    #     selected_items = self.table_widget.selectedItems()
    #     if selected_items:
    #         row = selected_items[0].row()
    #         packet = self.table_widget.item(row, 0).data(Qt.UserRole)
    #         if packet:
    #             packet_details.show_packet_details(packet)

    # def show_chart_window(self):
    #     self.chart_window = tubiao.ChartWindow(self.packet_count)
    #     self.chart_window.show()


class SniffThread(QThread):
    packet_received = pyqtSignal(list, object)

    def __init__(self, iface, filter_str):
        super().__init__()
        self.iface = iface
        self.filter_str = filter_str
        self.stop_sniffing_event = threading.Event()

    def run(self):
        try:
            sniff(iface=self.iface, prn=self.packet_handler, store=False,
                  stop_filter=lambda _: self.stop_sniffing_event.is_set(),filter=self.filter_str)
        except OSError as e:
            self.packet_received.emit(["Error opening adapter: " + str(e)], None)

    def packet_handler(self, packet):
        pkt_summary = []
        ethernet = packet.getlayer(Ether)
        ip = packet.getlayer(IP)
        tcp = packet.getlayer(TCP)
        udp = packet.getlayer(UDP)
        icmp = packet.getlayer(ICMP)
        arp = packet.getlayer(ARP)
        dns = packet.getlayer(DNS)

        if ip:
            if tcp:
                pkt_summary.append("TCP")
            elif udp:
                if dns:
                    pkt_summary.append("DNS")
                else:
                    pkt_summary.append("UDP")
            elif icmp:
                pkt_summary.append("ICMP")
            else:
                pkt_summary.append("IP")

            pkt_summary.append(ip.src)
            pkt_summary.append(ip.dst)
            pkt_summary.append(str(len(packet)))  # Packet length
        elif arp:
            pkt_summary.extend(["ARP", arp.psrc, arp.pdst, "28"])  # ARP packets are 28 bytes long
        else:
            pkt_summary.extend(["IPv6", "-", "-", "-"])

        self.packet_received.emit(pkt_summary, packet)


if __name__ == '__main__':
    app = QApplication([])
    window = PacketSnifferWindow()
    window.show()
    app.exec_()


