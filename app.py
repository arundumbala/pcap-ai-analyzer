import os
from datetime import datetime
from dotenv import load_dotenv
from flask import Flask, flash, jsonify, redirect, render_template, request, url_for
from google import genai
from scapy.all import DNS, ICMP, IP, TCP, UDP, Raw, rdpcap
from werkzeug.utils import secure_filename

load_dotenv()
api_key = os.getenv('GEMINI_API_KEY')
client = genai.Client(api_key=api_key)

UPLOAD_FOLDER = os.path.join(os.path.dirname(__file__), 'uploads')
ALLOWED_EXTENSIONS = {'pcap'}

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16 MB max upload size
app.secret_key = 'replace-with-a-secure-random-secret'  # replace before production

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)


def allowed_file(filename: str) -> bool:
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route('/', methods=['GET'])
def index():
    return render_template('index.html', total_packets=0, unique_ips=[], protocols={}, packet_log=[], filename=None)


@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        flash('No file part in the request.')
        return render_template('index.html', total_packets=0, unique_ips=[], filename=None)

    file = request.files['file']
    if file.filename == '':
        flash('No file selected.')
        return render_template('index.html', total_packets=0, unique_ips=[], filename=None)

    if not allowed_file(file.filename):
        flash('Only .pcap files are allowed.')
        return render_template('index.html', total_packets=0, unique_ips=[], filename=None)

    filename = secure_filename(file.filename)
    if filename == '':
        flash('Invalid file name.')
        return render_template('index.html', total_packets=0, unique_ips=[], filename=None)

    destination = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(destination)

    try:
        packets = rdpcap(destination)
    except Exception as error:
        flash(f'Uploaded file saved, but could not read pcap: {error}')
        return render_template('index.html', total_packets=0, unique_ips=[], protocols={}, packet_log=[], filename=None)

    unique_ips = set()
    protocols = {
        'TCP': 0,
        'UDP': 0,
        'ICMP': 0,
        'DNS': 0,
        'Other': 0,
    }
    packet_log = []

    for index, packet in enumerate(packets, start=1):
        timestamp = datetime.fromtimestamp(float(packet.time)).strftime('%Y-%m-%d %H:%M:%S')
        src_ip = packet[IP].src if packet.haslayer(IP) else 'N/A'
        dst_ip = packet[IP].dst if packet.haslayer(IP) else 'N/A'

        src_port = 'N/A'
        dst_port = 'N/A'
        flags = ''
        if packet.haslayer(TCP):
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            flags = str(packet[TCP].flags)
        elif packet.haslayer(UDP):
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport

        if packet.haslayer(DNS):
            protocols['DNS'] += 1
        elif packet.haslayer(TCP):
            protocols['TCP'] += 1
        elif packet.haslayer(UDP):
            protocols['UDP'] += 1
        elif packet.haslayer(ICMP):
            protocols['ICMP'] += 1
        else:
            protocols['Other'] += 1

        payload_snippet = ''
        if packet.haslayer(Raw):
            raw_bytes = bytes(packet[Raw].load)
            try:
                raw_text = raw_bytes.decode('utf-8', errors='ignore')
            except Exception:
                raw_text = raw_bytes.decode('latin-1', errors='ignore')
            raw_lines = [line.strip() for line in raw_text.splitlines() if line.strip()]
            if raw_lines:
                payload_snippet = raw_lines[0]
                if len(payload_snippet) > 120:
                    payload_snippet = payload_snippet[:120] + '...'

        log_entry = [
            f"[{index}] {timestamp}",
            f"{src_ip}:{src_port} -> {dst_ip}:{dst_port}",
        ]
        if flags:
            log_entry.append(f"Flags: {flags}")
        if payload_snippet:
            log_entry.append(f"Payload: {payload_snippet}")

        packet_log.append(' | '.join(log_entry))

        if packet.haslayer(IP):
            unique_ips.add(packet[IP].src)

    return render_template(
        'index.html',
        filename=filename,
        total_packets=len(packets),
        unique_ips=sorted(unique_ips),
        protocols=protocols,
        packet_log=packet_log,
    )


@app.route('/ask_ai', methods=['POST'])
def ask_ai():
    data = request.get_json(silent=True) or {}
    question = data.get('question')
    pcap_context = data.get('pcap_context')
    protocols = data.get('protocols')
    packet_log = data.get('packet_log')

    if not question or not pcap_context or protocols is None or packet_log is None:
        return jsonify({'error': 'question, pcap_context, protocols, and packet_log are required.'}), 400

    packet_log_text = '\n'.join(packet_log) if isinstance(packet_log, list) else str(packet_log)
    prompt_text = (
        f"Context: {pcap_context}\n"
        f"Protocols: {protocols}\n"
        f"Packet log:\n{packet_log_text}\n"
        f"Question: {question}"
    )

    try:
        response = client.models.generate_content(
            model='gemini-3.5-flash',
            contents=prompt_text,
        )

        text_response = getattr(response, 'text', None)
        if text_response is None:
            raise ValueError('AI did not return text.')

        return jsonify({'answer': text_response})

    except Exception as e:
        print(e)
        return jsonify({'error': str(e)}), 500


if __name__ == '__main__':
    app.run(debug=True)
