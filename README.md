SDN DDoS Detection and Mitigation

SDN-based DoS/DDoS detection and mitigation using Ryu, OpenFlow, Mininet and Machine Learning.

1. Install WSL and Ubuntu

On Windows, open PowerShell as Administrator:

wsl --install

Restart the computer and open Ubuntu.

Check WSL:

wsl -l -v

Ubuntu should use WSL 2.

2. Update Ubuntu

Inside Ubuntu:

sudo apt update
sudo apt upgrade -y
sudo apt install -y git python3 python3-pip python3-venv build-essential

3. Install Mininet and Open vSwitch

Mininet is installed separately from requirements.txt.

sudo apt install -y mininet openvswitch-switch
sudo service openvswitch-switch start

Check:

mn --version
python3 -c "import mininet; print('Mininet OK')"

Test:

sudo mn --switch ovsbr --test pingall
sudo mn -c

4. Clone the Project

cd ~
git clone https://github.com/Kaushikshetty123/DDos-Detection.git
cd ~/DDos-Detection

5. Create the Python Virtual Environment

python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt

Check Ryu:

ryu-manager --version

Ryu and ML dependencies run inside the virtual environment. Mininet uses the Ubuntu system Python.

6. Start the Ryu Controller

Terminal 1:

cd ~/DDos-Detection
source venv/bin/activate
SDN_MODE=detect ryu-manager --ofp-tcp-listen-port 6633 ryu_controller.py

Keep it running.

7. Start Mininet

Terminal 2:

cd ~/DDos-Detection
sudo mn -c
sudo python3 topology.py

Network:

h1 = 10.0.0.1  (attacker)
h2 = 10.0.0.2  (victim)
h3 = 10.0.0.3  (attacker)
h4 = 10.0.0.4  (attacker)
s1 = OpenFlow switch

Wait for:

[OK] Controller connected.

8. Test Normal Traffic

Inside Mininet:

h1 ping -c 10 10.0.0.2

Expected: normal traffic.

9. Test Single-Source DoS

Start a clean topology if needed:

exit
sudo mn -c
sudo python3 topology.py

Then:

h1 ping -f 10.0.0.2

Let it run for a few seconds and press Ctrl+C.

The controller should detect a single-source DoS and block the attacking source after confirmation.

Check switch rules:

sh ovs-ofctl -O OpenFlow13 dump-flows s1

10. Test Distributed DDoS

Start a clean topology:

exit
sudo mn -c
sudo python3 topology.py

Run all attackers:

h1 ping -f 10.0.0.2 > /dev/null 2>&1 &
h3 ping -f 10.0.0.2 > /dev/null 2>&1 &
h4 ping -f 10.0.0.2 > /dev/null 2>&1 &

Let them run for about 15–20 seconds.

The controller aggregates traffic going to the victim and detects distributed DDoS when the aggregate conditions and multiple-source confirmation are satisfied.

Stop the floods:

sh pkill -f 'ping -f'

Check mitigation:

sh ovs-ofctl -O OpenFlow13 dump-flows s1

Blocked attackers should have high-priority drop rules.

11. Run the Web Dashboard

Keep Ryu running in Terminal 1.

Terminal 2:

cd ~/DDos-Detection
sudo python3 dashboard_backend.py

Open in a Windows browser:

http://localhost:8080

The dashboard shows attack configuration, traffic statistics, switch monitoring, victim monitoring, detection events, blocked sources and network-flow visualization.

12. Clean Up

Stop floods:

sh pkill -f 'ping -f'

Exit Mininet:

exit

Clean Mininet:

sudo mn -c

13. Troubleshooting

Ryu command not found

source venv/bin/activate
pip install -r requirements.txt

Mininet not found

sudo apt update
sudo apt install -y mininet openvswitch-switch

Controller connection problem

Start Ryu first:

source venv/bin/activate
SDN_MODE=detect ryu-manager --ofp-tcp-listen-port 6633 ryu_controller.py

Then start Mininet:

sudo mn -c
sudo python3 topology.py

Stale Mininet network

sudo mn -c

Quick Start After Initial Setup

Terminal 1:

cd ~/DDos-Detection
source venv/bin/activate
SDN_MODE=detect ryu-manager --ofp-tcp-listen-port 6633 ryu_controller.py

Terminal 2:

cd ~/DDos-Detection
sudo mn -c
sudo python3 topology.py

Dashboard:

cd ~/DDos-Detection
sudo python3 dashboard_backend.py

Open:

http://localhost:8080