import tkinter as tk
from tkinter import scrolledtext
from scapy.all import sniff, Ether, IP, UDP, TCP
from collections import defaultdict
import threading

class NetworkScannerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Network Scanner")
        
        self.text_area = scrolledtext.ScrolledText(root, width=80, height=20)
        self.text_area.pack(padx=10, pady=10)
        
        self.start_button = tk.Button(root, text="Start Scan", command=self.start_scan)
        self.start_button.pack(pady=5)
        
        self.stop_button = tk.Button(root, text="Stop Scan", command=self.stop_scan, state=tk.DISABLED)
        self.stop_button.pack(pady=5)
        
        self.iot_devices = defaultdict(dict)
        self.sniffing_thread = None

    def process_packet(self, packet):
        if IP in packet:
            src_mac = packet[Ether].src
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst

            if UDP in packet and packet[UDP].dport == 53:
                self.iot_devices[src_mac]["tipo"] = "Dispositivo de domótica"
            elif TCP in packet and packet[TCP].dport == 80:
                self.iot_devices[src_mac]["tipo"] = "Cámara de seguridad"
            else:
                self.iot_devices[src_mac]["tipo"] = "Desconocido"

            self.iot_devices[src_mac]["ip"] = src_ip
            self.iot_devices[src_mac]["paquetes_enviados"] += 1
            self.iot_devices[src_mac]["paquetes_recibidos"] += 1

    def start_scan(self):
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.text_area.delete('1.0', tk.END)
        self.text_area.insert(tk.END, "Iniciando escaneo...\n")
        self.iot_devices.clear()
        self.sniffing_thread = threading.Thread(target=self.sniff_network)
        self.sniffing_thread.start()

    def stop_scan(self):
        if self.sniffing_thread and self.sniffing_thread.is_alive():
            self.text_area.insert(tk.END, "Deteniendo escaneo...\n")
            self.sniffing_thread.join()
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        self.print_iot_devices()

    def sniff_network(self):
        sniff(prn=self.process_packet, store=0)

    def print_iot_devices(self):
        self.text_area.insert(tk.END, "Dispositivos IoT detectados:\n")
        for mac, info in self.iot_devices.items():
            self.text_area.insert(tk.END, f"MAC: {mac}, IP: {info['ip']}, Tipo: {info['tipo']}, Paquetes enviados: {info['paquetes_enviados']}, Paquetes recibidos: {info['paquetes_recibidos']}\n")
        self.text_area.insert(tk.END, "\n")

if __name__ == "__main__":
    root = tk.Tk()
    app = NetworkScannerApp(root)
    root.mainloop()
