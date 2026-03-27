## License

📜 This project is **source-available but not open source**.

You may view the source code for learning or evaluation, but **commercial use, modification, or redistribution is prohibited** without permission.

See the [LICENSE](./LICENSE) file for details.



# Pman - Packet Manipulator
![pmanlogo](https://github.com/user-attachments/assets/36483476-a030-482c-a1df-34fd86ace80d)

**Pman** is a GUI-based packet crafting and manipulation tool that offers the powerful functionality of tools like Scapy, but in a user-friendly, visual interface. Designed for cybersecurity researchers, penetration testers, and network engineers who prefer working with packets in a more intuitive way.

---

## 🚀 Features

- 🌐 Create, edit, and send custom packets
- 📦 Full support for TCP, UDP, ICMP, ARP, and more
- 🧩 Layered packet building (just like Scapy)
- 🖥️ Intuitive GUI interface (no need to write code!)
- 🧪 Packet sniffing and filtering
- 📊 Real-time visualization of traffic
- 🔄 Packet replay functionality
- 🔧 Modular architecture for future extensions

---

## 🎯 Who It's For

- Penetration testers who want quick packet manipulation without scripts
- Networking students learning about protocols
- Cybersecurity researchers testing firewall behavior or crafting exploits
- Anyone who wants Scapy-like power without the CLI

## 📦 Installation

```bash
# Clone the repo
git clone https://github.com/YaminHaris/pman.git
cd pman

# (Optional) Create a virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
# (Ensure scapy and tkinter are installed)
pip install scapy

# Run the GUI
python src/main.py
```
