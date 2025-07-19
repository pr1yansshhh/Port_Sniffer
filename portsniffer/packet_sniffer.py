from scapy.all import sniff, IP
from datetime import datetime

LOG_TEXT_FILE = "packet_log.txt"
HTML_REPORT_FILE = "packet_report.html"
PACKET_COUNT = 20      
PORT_FILTER = "tcp port 443" # Change as needed (e.g., "ip", "tcp", "udp", "port 443")

def log_packet(packet):
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        proto = packet[IP].proto
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        log_entry = f"{timestamp} | {ip_src} → {ip_dst} | Protocol: {proto}\n"
        print(log_entry.strip())

        with open(LOG_TEXT_FILE, "a") as f:
            f.write(log_entry)

# Generate HTML report from log file
def generate_html_report(txt_file, html_file):
    try:
        with open(txt_file, "r") as f:
            lines = f.readlines()
    except FileNotFoundError:
        print("No log file found to convert.")
        return

    with open(html_file, "w") as f:
        f.write("<html><head><title>Packet Log Report</title></head><body>")
        f.write("<h2>📄 Packet Log Report</h2><pre style='font-family:monospace;'>\n")
        for line in lines:
            f.write(line)
        f.write("</pre></body></html>")
    
    print(f"[+] HTML Report saved to: {html_file}")

def start_sniffing():
    print(f"[+] Starting packet capture on filter: {PORT_FILTER}")
    sniff(prn=log_packet, filter=PORT_FILTER, store=0, count=PACKET_COUNT)
    print(f"[✓] Packet capture complete. Log saved to: {LOG_TEXT_FILE}")
    generate_html_report(LOG_TEXT_FILE, HTML_REPORT_FILE)

if __name__ == "__main__":
    start_sniffing()
