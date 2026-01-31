# MiMiNet  
**Low-Cost Wi-Fi Probe Capture & Captive Portal Project**

⚠️ **Educational & Ethical Use Only**  
This project is intended strictly for **authorized lab environments** and **ethical security research**.

---

## Overview

**MiMiNet** is a learning-focused project that demonstrates how Wi-Fi probe requests from nearby devices can be captured and how a simple captive portal system can be deployed using low-cost hardware.

Inspired by commercial tools such as the *WiFi Pineapple*, MiMiNet emphasizes **experimentation, understanding, and affordability** rather than real-world deployment.

---

## Features

- Capture Wi-Fi probe requests from nearby devices  
- Extract and display SSIDs that devices are searching for  
- Create a fake access point using a selected SSID  
- Serve a lightweight captive portal for connected clients  
- Log submitted credentials to a local file for research analysis  

---

## Hardware Requirements

- USB Wi-Fi adapter supporting **monitor mode** and **AP mode**
- Linux laptop or PC  
  - **Kali Linux recommended**

---

## Software Requirements

- Python 3  
- **Scapy** for packet sniffing  
  ```bash
  pip install scapy

