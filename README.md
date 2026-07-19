# 🕵️‍♂️ AI-Powered Network Traffic (PCAP) Analyzer

**Live Demo:** [https://pcap-ai-analyzer.onrender.com](https://pcap-ai-analyzer.onrender.com)

## 📌 Project Overview
[cite_start]An AI-powered Network Traffic Analyzer built with Python, Flask, and the Google Gemini API[cite: 1798]. This application allows users to securely upload binary `.pcap` files, extracts the raw network data, and provides an interactive AI chat interface to act as a forensic network analyst.

## 🚀 Key Features
* **Secure File Handling:** Uses Werkzeug's `secure_filename` and strict extension validation to ensure only legitimate `.pcap` files are processed safely.
* **Deep Packet Extraction:** Leverages `scapy` to parse binary network captures, extracting key forensic data like total packets, unique IPs, timestamps, ports, and TCP flags.
* **AI-Powered Threat Intelligence:** Integrates the Google Gemini 3.5 Flash model to answer complex, natural language questions about the uploaded network traffic.
* **Modern Interface:** Features a sleek, dark-themed, responsive dashboard built with Tailwind CSS.

## 🔐 Security Best Practices Implemented
Security was a core focus in the architecture of this application:
* [cite_start]**Strict Secrets Management:** API keys are injected via environment variables (`.env`) and are explicitly blocked from version control using `.gitignore`[cite: 1401, 1402]. 
* [cite_start]**Runtime Injection:** Secured the cloud deployment by utilizing Render's native Environment Variables dashboard for runtime secrets management[cite: 1683, 1684].
* [cite_start]**Data Privacy:** `.pcap` files are strictly excluded from version control to prevent accidental leaks of sensitive network data[cite: 1301, 1302].

## 🛠️ Technology Stack
* **Backend:** Python, Flask, Gunicorn
* **Network Parsing:** Scapy
* **Artificial Intelligence:** Google Gemini API (`google-genai` SDK)
* **Frontend:** HTML5, Tailwind CSS
* **Cloud Deployment:** Render (Linux/Ubuntu environment)

## 💻 Running the Project Locally

If you want to run this project on your local machine, follow these steps:

1. **Clone the repository:**
   ```bash
   git clone [https://github.com/your-username/pcap-ai-analyzer.git](https://github.com/your-username/pcap-ai-analyzer.git)
   cd pcap-ai-analyzer
   
2. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
3. **Set up your environment variables:**
   Create a .env file in the root directory.
   Add your Google Gemini API key:
   ```bash
   GEMINI_API_KEY=your_api_key_here
5. **Run the Flask server:**
   ```bash
   python app.py
6. **Accessing the application:**
   Navigate to http://127.0.0.1:5000
