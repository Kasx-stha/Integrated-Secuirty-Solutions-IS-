# Import required libraries for datetime, system interaction, plotting, PDF generation, email sending, and regex
import datetime
import os
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
from email.mime.text import MIMEText
import re

# File paths and email configuration
IDS_LOG_PATH = "/home/kali/IDS/ids.log"
IPS_LOG_PATH = "/usr/local/etc/snort/alert_fast.txt"
EMAIL_CREDENTIALS = {
    "from_email": "kasxstha@gmail.com",
    "to_email": "shresthakashish0@gmail.com",
    "password": "wjjkxitgsjmcahdq"  
}
logo_path = "/home/kali/Project/frontend/static/images/LOGO.png"

# Determine reporting time window: from yesterday 5 PM to today 5 PM
now = datetime.datetime.now()
today_5pm = now.replace(hour=17, minute=0, second=0, microsecond=0)

if now < today_5pm:
    end_time = today_5pm
else:
    end_time = today_5pm
start_time = end_time - datetime.timedelta(days=1)

# Show debug window range
print("▶️ DEBUG TIME WINDOW")
print("Now:        ", now)
print("Start Time: ", start_time)
print("End Time:   ", end_time)

# Parse a multiline IDS log entry and extract structured information
def parse_ids_log_line_multiline(lines):
    event = {}
    for line in lines:
        line = line.strip()
        if "[ALERT]" in line:
            event["attack_type"] = line.split("[ALERT]")[-1].strip()
        elif line.startswith("Timestamp:"):
            event["timestamp"] = line.split("Timestamp:")[1].strip()
        elif line.startswith("Source:"):
            event["source_ip"] = line.split("Source:")[1].strip()
        elif line.startswith("Destination:"):
            event["dest_ip"] = line.split("Destination:")[1].strip()

    if all(k in event for k in ["timestamp", "attack_type", "source_ip", "dest_ip"]):
        try:
            ts = datetime.datetime.strptime(event["timestamp"], "%Y-%m-%d %H:%M:%S")
            if start_time <= ts < end_time:
                print(f"[DEBUG] Included log at {event['timestamp']} : {event['attack_type']}")
                return f"{event['timestamp']} - {event['attack_type']} from {event['source_ip']} to {event['dest_ip']}"
            else:
                print(f"[DEBUG] Skipped log at {event['timestamp']} (out of range)")
        except ValueError:
            print(f"[DEBUG] Invalid timestamp format in line block: {event.get('timestamp')}")
    return None

# Read and parse IDS logs

def fetch_ids_logs():
    logs = []
    try:
        with open(IDS_LOG_PATH, "r") as f:
            lines = f.readlines()

        buffer = []
        for line in lines:
            if "[ALERT]" in line and buffer:
                parsed = parse_ids_log_line_multiline(buffer)
                if parsed:
                    logs.append(parsed)
                buffer = [line]
            else:
                buffer.append(line)

        if buffer:
            parsed = parse_ids_log_line_multiline(buffer)
            if parsed:
                logs.append(parsed)

        return logs
    except Exception as e:
        print(f"[!] IDS log error: {str(e)}")
        return []

# Read and filter IPS logs (Snort fast alert format)
def fetch_ips_logs():
    logs = []
    try:
        with open(IPS_LOG_PATH, "r") as f:
            lines = f.readlines()

        current_year = datetime.datetime.now().year

        for line in lines:
            line = line.strip()
            match = re.match(r"(\d{2}/\d{2})-(\d{2}:\d{2}:\d{2}\.\d+)", line)
            if match:
                date_part = match.group(1)  # MM/DD
                time_part = match.group(2)  # HH:MM:SS.micro
                timestamp_str = f"{current_year}/{date_part} {time_part.split('.')[0]}"
                try:
                    ts = datetime.datetime.strptime(timestamp_str, "%Y/%m/%d %H:%M:%S")
                    if start_time <= ts < end_time:
                        print(f"[DEBUG] Included IPS log at {ts}")
                        logs.append(line)
                    else:
                        print(f"[DEBUG] Skipped IPS log at {ts} (out of range)")
                except ValueError as ve:
                    print(f"[DEBUG] Error parsing timestamp: {timestamp_str} - {ve}")
        return logs

    except Exception as e:
        print(f"[!] IPS log error: {str(e)}")
        return []

# Categorize logs into attack types and identify suspicious source IPs
def categorize_logs(logs):
    if not logs:
        return {}, []

    patterns = {
        "SQL Injection": re.compile(r"sql.*injection|SQL_Injection_Basic", re.I),
        "XSS": re.compile(r"cross.?site.?scripting|xss", re.I),
        "DDoS": re.compile(r"ddos|icmp flood|DoS|packet rate exceeded", re.I),
        "Phishing": re.compile(r"phishing|Phishing Attempt", re.I),
        "Malware": re.compile(r"malware|trojan|virus|worm|exploit", re.I),
        "Dark Web": re.compile(r"dark web|tor|onion|black market|dns tunnel|base64", re.I)
    }

    counts = {attack: 0 for attack in patterns}
    ip_counter = Counter()

    for log in logs:
        for attack, pattern in patterns.items():
            if pattern.search(log):
                counts[attack] += 1

        # Only count source IPs (not destination)
        src_match = re.search(r"from (\d{1,3}(?:\.\d{1,3}){3})", log)
        if src_match:
            ip_counter.update([src_match.group(1)])

    return counts, ip_counter.most_common(5)

# Generate the PDF report with summaries, tables, and charts
def create_pdf_report(report_filename, attack_counts, top_ips, logo_path):
    doc = SimpleDocTemplate(report_filename, pagesize=letter)
    styles = getSampleStyleSheet()
    story = []

    # Define text styles
    title_style = ParagraphStyle('Title', parent=styles['Title'], fontSize=24, spaceAfter=24, alignment=1)
    normal_style = ParagraphStyle('Normal', parent=styles['Normal'], leading=18)
    list_style = ParagraphStyle('Heading4', parent=styles['Heading4'], leading=18, alignment=1)
    heading_style = ParagraphStyle('Heading1', parent=styles['Heading1'], spaceAfter=12)

    # Cover Page
    story.append(Spacer(1, 100))
    story.append(Image(logo_path, width=2 * inch, height=2 * inch))
    story.append(Spacer(1, 50))
    story.append(Paragraph("Integrated Security Solutions", title_style))
    story.append(Spacer(1, 12))
    story.append(Paragraph("Daily Security Report", title_style))
    story.append(Spacer(1, 50))
    story.append(PageBreak())

    # Intro Page
    story.append(Spacer(1, 250))
    story.append(Paragraph("This report is generated via Integrated Security Solutions (IS)", list_style))
    story.append(Spacer(1, 20))
    story.append(Paragraph(f"Generated at: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", list_style))
    story.append(PageBreak())

    # Table of Contents
    story.append(Paragraph("Table of Contents", heading_style))
    story.append(Spacer(1, 12))
    story.append(Paragraph("1. Attack Summary", normal_style))
    story.append(Spacer(1, 6))
    story.append(Paragraph("2. Suspicious IP Addresses", normal_style))
    story.append(Spacer(1, 6))
    story.append(Paragraph("3. Attack Types Distribution", normal_style))
    story.append(PageBreak())

    # Attack Summary
    story.append(Paragraph("1. Attack Summary", heading_style))
    story.append(Spacer(1, 12))
    story.append(Paragraph("The table below provides a summary of the attacks for today.", normal_style))
    story.append(Spacer(1, 12))

    table_data = [["Attack Type", "Count"]]
    for attack, count in attack_counts.items():
        table_data.append([attack, str(count)])

    # Format summary table
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

    # Suspicious IP Section
    story.append(Paragraph("2. Suspicious IP Addresses", heading_style))
    story.append(Spacer(1, 12))

    ip_data = [["IP Address", "Count"]]
    for ip, count in top_ips:
        ip_data.append([ip, str(count)])

    # Format suspicious IP table
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

    # Attack Chart
    story.append(Paragraph("3. Attack Types Distribution", heading_style))
    story.append(Spacer(1, 12))
    story.append(Paragraph("The bar chart below illustrates the different types of attacks detected by the Integrated Security Solution (IS).", normal_style))

    total_attacks = sum(attack_counts.values())
    if total_attacks > 0:
        labels = [attack for attack, count in attack_counts.items() if count > 0]
        values = [count for attack, count in attack_counts.items() if count > 0]

        # Build the bar chart
        plt.figure(figsize=(10, 5))
        bars = plt.bar(labels, values)
        plt.yscale('log')
        plt.xlabel("Attack Type")
        plt.ylabel("Count (Log Scale)")
        plt.title("Attack Types Distribution")
        plt.xticks(rotation=45)

        for bar in bars:
            yval = bar.get_height()
            plt.text(bar.get_x() + bar.get_width()/2, yval, f'{int(yval)}', ha='center', va='bottom', fontsize=8)

        chart_path = "/tmp/attack_chart.png"
        plt.tight_layout()
        plt.savefig(chart_path)
        plt.close()

        # Add chart to PDF
        story.append(Spacer(1, 30))
        story.append(Image(chart_path, width=5.5*inch, height=3*inch))
        story.append(Spacer(1, 12))
        story.append(Paragraph("Figure 1: Distribution of detected attack types.", list_style))
    else:
        story.append(Paragraph("No attacks detected during the reporting period.", normal_style))

    # Page numbering
    def add_page_number(canvas, doc):
        page_num = canvas.getPageNumber()
        text = f"Page {page_num}"
        canvas.setFont("Helvetica", 9)
        canvas.drawRightString(6.5*inch, 0.5*inch, text)

    doc.build(story, onFirstPage=add_page_number, onLaterPages=add_page_number)

# Send the generated PDF via email
def send_email_with_attachment(report_filename):
    msg = MIMEMultipart()
    msg['From'] = EMAIL_CREDENTIALS['from_email']
    msg['To'] = EMAIL_CREDENTIALS['to_email']
    msg['Subject'] = "Daily Security Report - " + datetime.datetime.now().strftime("%Y-%m-%d")

    body = "Dear Admin,\n\nPlease find the attached daily security report from Integrated Security Solutions. This is an automated report.\n\nSincerely,\n\nIntegrated Security Solutions (IS)"
    msg.attach(MIMEText(body))

    try:
        with open(report_filename, "rb") as f:
            part = MIMEBase('application', 'octet-stream')
            part.set_payload(f.read())
        encoders.encode_base64(part)
        part.add_header('Content-Disposition', f'attachment; filename="{os.path.basename(report_filename)}"')
        msg.attach(part)
    except FileNotFoundError:
        print(f"[!] Report file {report_filename} not found.")
        return

    try:
        with smtplib.SMTP('smtp.gmail.com', 587) as server:
            server.starttls()
            server.login(EMAIL_CREDENTIALS['from_email'], EMAIL_CREDENTIALS['password'])
            server.send_message(msg)
        print("[+] Email sent successfully.")
    except Exception as e:
        print(f"[!] Email failed: {str(e)}")

# Main execution logic
if __name__ == "__main__":
    ids_logs = fetch_ids_logs()
    ips_logs = fetch_ips_logs()
    all_logs = ids_logs + ips_logs

    if not all_logs:
        print("[!] No logs collected - skipping report generation.")
    else:
        attack_counts, top_ips = categorize_logs(all_logs)
        report_filename = f"Integrated_Security_Daily_Report_{datetime.datetime.now().strftime('%Y%m%d')}.pdf"
        create_pdf_report(report_filename, attack_counts, top_ips, logo_path)
        send_email_with_attachment(report_filename)
