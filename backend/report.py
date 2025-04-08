import datetime
import requests
import os
import json
import matplotlib.pyplot as plt
from collections import Counter
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.pdfgen import canvas
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    PageBreak,
    Image
)
from reportlab.lib.units import inch
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
import re
from email.mime.text import MIMEText
from fpdf import FPDF

# -------------------------------------------------
# Configuration
# -------------------------------------------------
GRAYLOG_URL = "http://192.168.196.128:9000/api/search/universal/relative"
GRAYLOG_HEADERS = {
    "X-Requested-By": "PythonScript",
    "Authorization": "Basic YWRtaW46QWJjZC4xMjM=",
    "Accept": "application/json"
}
IDS_LOG_PATH = "/home/kali/IDS/ids.log"
IPS_LOG_PATH = "/usr/local/etc/snort/alert_fast.txt"

EMAIL_CREDENTIALS = {
    "from_email": "kasxstha@gmail.com",
    "to_email": "shresthakashish0@gmail.com",
    "password": "wjjkxitgsjmcahdq"  
}

logo_path = "/home/kali/Project/frontend/static/images/LOGO.png"

# -------------------------------------------------
# Functions
# -------------------------------------------------

def fetch_graylog_logs():
    """Fetch logs from Graylog API with JSON handling."""
    try:
        response = requests.get(
            GRAYLOG_URL,
            headers=GRAYLOG_HEADERS,
            params={
                "query": "*",
                "range": 86400,
                "limit": 100,
                "filter": "streams:000000000000000000000001"
            },
            verify=False
        )
        response.raise_for_status()

        logs = []
        for message in response.json().get('messages', []):
            log = message.get('message', {})
            logs.append({
                "timestamp": log.get('timestamp'),
                "message": log.get('message'),
                "source": log.get('source')
            })
        return logs

    except Exception as e:
        print(f"[!] Graylog API error: {str(e)}")
        return []


def parse_ids_log_line(line):
    """Parse a single IDS log line."""
    patterns = [
        re.compile(
            r"(\d{2}/\d{2}/\d{4}-\d{2}:\d{2}:\d{2}\.\d+)\s+\[.*?\]\s+([\w\s]+?)\s+(\d+\.\d+\.\d+\.\d+):\d+\s+->\s+(\d+\.\d+\.\d+\.\d+):\d+"
        ),
        re.compile(
            r"\[.*?\]\s+(\d+\.\d+\.\d+\.\d+):\d+\s+->\s+(\d+\.\d+\.\d+\.\d+):\d+.*?\[Classification:\s+(.*?)\]\s+\[Priority:\s+\d+\]"
        )
    ]

    for pattern in patterns:
        match = pattern.search(line)
        if match:
            if len(match.groups()) == 4:
                return {
                    "timestamp": match.group(1),
                    "attack_type": match.group(2).strip(),
                    "source_ip": match.group(3),
                    "dest_ip": match.group(4)
                }
            elif len(match.groups()) == 3:
                return {
                    "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "attack_type": match.group(3).strip(),
                    "source_ip": match.group(1).split(":")[0],
                    "dest_ip": match.group(2).split(":")[0]
                }
    return None


def fetch_ids_logs():
    """Fetch and parse IDS logs."""
    logs = []
    try:
        with open(IDS_LOG_PATH, "r") as f:
            for line in f:
                parsed = parse_ids_log_line(line)
                if parsed:
                    logs.append(
                        f"{parsed['timestamp']} - {parsed['attack_type']} "
                        f"from {parsed['source_ip']} to {parsed['dest_ip']}"
                    )
        return logs
    except Exception as e:
        print(f"[!] IDS log error: {str(e)}")
        return []


def fetch_ips_logs():
    """Fetch IPS logs."""
    try:
        with open(IPS_LOG_PATH, "r") as f:
            return [line.strip() for line in f.readlines()]
    except Exception as e:
        print(f"[!] IPS log error: {str(e)}")
        return []


def categorize_logs(logs):
    """Categorize logs by attack types and count top IPs."""
    patterns = {
        "SQL Injection": re.compile(r"sql.*?injection|union.*?select", re.I),
        "XSS": re.compile(r"<script>|xss", re.I),
        "DDoS": re.compile(r"flood|ddos|syn.*?ack", re.I),
        "Buffer Overflow": re.compile(r"overflow|buffer", re.I),
        "DNS Tunneling": re.compile(r"dns.*?tunnel|base64.*?query", re.I),
        "Port Scan": re.compile(r"port.*?scan|multiple.*?ports", re.I)
    }

    counts = {attack: 0 for attack in patterns}
    ip_counter = Counter()

    for log in logs:
        for attack, pattern in patterns.items():
            if pattern.search(log):
                counts[attack] += 1
        ips = re.findall(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", log)
        ip_counter.update(ips)

    return counts, ip_counter.most_common(5)


def create_pdf_report(report_filename, attack_counts, top_ips, logo_path):
    """Create a PDF report with attack summaries, charts, and a logo."""
    doc = SimpleDocTemplate(report_filename, pagesize=letter)
    styles = getSampleStyleSheet()
    story = []

    # Custom Centered Title Style
    title_style = ParagraphStyle(
        'Title',
        parent=styles['Title'],
        fontSize=24,
        spaceAfter=24,
        alignment=1  # Center alignment
    )

    # Normal style with 1.5 line spacing
    normal_style = ParagraphStyle(
        'Normal',
        parent=styles['Normal'],
        leading=18  # 1.5 * default line height
    )
    
    list_style = ParagraphStyle(
         'Heading4',
          parent=styles['Heading4'],
          leading=18,
          alignment=1
    )

    # Heading style with 1.5 spacing
    heading_style = ParagraphStyle(
        'Heading1',
        parent=styles['Heading1'],
        spaceAfter=12,
    )


    # Cover Page (All elements centered)
    story.append(Spacer(1,100))
    story.append(Image(logo_path, width=2 * inch, height=2 * inch)) 
    story.append(Spacer(1,50))
    story.append(Paragraph("Integrated Security Solutions", title_style))
    story.append(Spacer(1, 12))
    story.append(Paragraph("Daily Security Report", title_style))
    story.append(Spacer(1, 50))
    story.append(PageBreak())

    story.append(Spacer(1,250))
    story.append(Paragraph("This report is generated via Integrated Security Solutions (IS)", list_style))
    story.append(Spacer(1, 20))
    story.append(Paragraph(f"Generated at: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", list_style))
    story.append(PageBreak())

    # Table of Contents (TOC) - 1.5 line spacing
    story.append(Paragraph("Table of Contents", heading_style))
    story.append(Spacer(1, 12))
    story.append(Paragraph("1. Attack Summary", normal_style))
    story.append(Spacer(1, 6))
    story.append(Paragraph("2. Suspicious IP Addresses", normal_style))
    story.append(Spacer(1, 6))
    story.append(Paragraph("3. Attack Types Distribution", normal_style))
    story.append(PageBreak())

    # Attack Summary Table
    story.append(Paragraph("1. Attack Summary", heading_style))
    story.append(Spacer(1, 12))
    story.append(Paragraph("The table below provides a summary of the attacks for today. For detailed information, please refer to Graylog.", normal_style))
    story.append(Spacer(1, 12))

    table_data = [["Attack Type", "Count"]]
    for attack, count in attack_counts.items():
        table_data.append([attack, str(count)])

    attack_table = Table(table_data, colWidths=[300, 100])
    attack_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#4870a5')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#e1eeff')),
        ('GRID', (0, 0), (-1, -1), 1, colors.white)
    ]))
    story.append(attack_table)
    story.append(PageBreak())

    # Suspicious IPs Table
    story.append(Paragraph("2. Suspicious IP Addresses", heading_style))
    story.append(Spacer(1, 12))

    ip_data = [["IP Address", "Count"]]
    for ip, count in top_ips:
        ip_data.append([ip, str(count)])

    ip_table = Table(ip_data, colWidths=[300, 100])
    ip_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#4870a5')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#e1eeff')),
        ('GRID', (0, 0), (-1, -1), 1, colors.white)
    ]))
    story.append(ip_table)
    story.append(PageBreak())

    # Attack Distribution Chart
    story.append(Paragraph("3. Attack Types Distribution", heading_style))
    story.append(Spacer(1, 12))
    story.append(Paragraph("The pie chart below illustrates the different types of attacks detected by the Integrated Secuity Solution(IS).", normal_style))
    total_attacks = sum(attack_counts.values())
    if total_attacks > 0:
        # Generate Pie Chart
        plt.figure(figsize=(6, 6))
        labels = [attack for attack, count in attack_counts.items() if count > 0]
        sizes = [count for count in attack_counts.values() if count > 0]

        plt.pie(
            sizes,
            labels=labels,
            autopct='%1.1f%%',
            startangle=90,
            colors=['#e1eeff', '#66b3ff', '#99ff99', '#ffcc99', '#c2c2f0', '#ffb3e6']
        )
        plt.title("Attack Types Distribution")
        chart_path = "/tmp/attack_chart.png"
        plt.savefig(chart_path, format="png")
        plt.close()

        # Centered Image on Last Page
        story.append(Spacer(1, 60))  # Move image to center of the page
        story.append(Image(chart_path, width=4*inch, height=4*inch))
        story.append(Spacer(1, 12))
        story.append(Paragraph("Figure 1: Distribution of detected attack types.", list_style))
    else:
        story.append(Paragraph("No attacks detected during the reporting period.", normal_style))

    # Page Number Footer
    def add_page_number(canvas, doc):
        page_num = canvas.getPageNumber()
        text = f"Page {page_num}"
        canvas.setFont("Helvetica", 9)
        canvas.drawRightString(6.5*inch, 0.5*inch, text)

    doc.build(story, onFirstPage=add_page_number, onLaterPages=add_page_number)


# -------------------------------------------------
# Main Execution
# -------------------------------------------------
logs = fetch_ids_logs()
ips_logs = fetch_ips_logs()
graylog_logs = fetch_graylog_logs()

# Categorize logs and get attack counts and top IPs
attack_counts, top_ips = categorize_logs(logs)

# Create the report PDF
report_filename = "/tmp/security_report.pdf"
create_pdf_report(report_filename, attack_counts, top_ips, logo_path)

print(f"Report generated at {report_filename}")
def send_email_with_attachment(report_filename):
    """Send an email with the PDF report as attachment."""
    msg = MIMEMultipart()
    msg['From'] = EMAIL_CREDENTIALS['from_email']
    msg['To'] = EMAIL_CREDENTIALS['to_email']
    msg['Subject'] = "Daily Security Report - " + datetime.datetime.now().strftime("%Y-%m-%d")

    body = "Dear Admin, \n\n Please find the attached deaily security report from Integrated Secuirty Solutions. This is an automated report.\n\n Sincerely, \n\n Integrated Secuirty Solutions (IS)"
    msg.attach(MIMEText(body))

    try:
        with open(report_filename, "rb") as f:
            part = MIMEBase('application', 'octet-stream')
            part.set_payload(f.read())
        encoders.encode_base64(part)
        part.add_header(
            'Content-Disposition',
            f'attachment; filename="{os.path.basename(report_filename)}"'
        )
        msg.attach(part)
    except FileNotFoundError:
        print(f"[!] Report file {report_filename} not found.")
        return

    try:
        with smtplib.SMTP('smtp.gmail.com', 587) as server:
            server.starttls()
            server.login(
                EMAIL_CREDENTIALS['from_email'],
                EMAIL_CREDENTIALS['password']
            )
            server.send_message(msg)
        print("[+] Email sent successfully.")
    except Exception as e:
        print(f"[!] Email failed: {str(e)}")


# -------------------------------------------------
# Main Execution
# -------------------------------------------------
if __name__ == "__main__":
    graylog_logs = fetch_graylog_logs()
    ids_logs = fetch_ids_logs()
    ips_logs = fetch_ips_logs()

    all_logs = (
            [log['message'] for log in graylog_logs] +
            ids_logs +
            ips_logs
    )

    if not all_logs:
        print("[!] No logs collected - skipping report generation.")
    else:
        attack_counts, top_ips = categorize_logs(all_logs)
        report_filename = f"Integrated_Security_Daily_Report_{datetime.datetime.now().strftime('%Y%m%d')}.pdf"
        create_pdf_report(report_filename, attack_counts, top_ips, logo_path)
        send_email_with_attachment(report_filename)
