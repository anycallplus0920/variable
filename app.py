import customtkinter as ctk
import socket
import threading
import time
import struct  # 바이너리 데이터 조립용
from datetime import datetime

# =============================================================================
# [LAYER 0] Job Builder : 매뉴얼 96~105p 샘플 예제 데이터 조립
# =============================================================================
class JobBuilder:
    @staticmethod
    def create_example_job_payload():
        """
        매뉴얼 96p~105p의 'Sending a complete job to the library' 예제 바이너리 생성
        Job Name: EXAMPLE
        Content: Text, Date, External Variable, Barcode(DataMatrix)
        """
        # ---------------------------------------------------------
        # 1. Header (p97)
        # ---------------------------------------------------------
        # Job Type(11h CIJ), Version(01h)
        header = b'\x11\x01'
        # Job Name "EXAMPLE" (20 bytes, null padded)
        header += "EXAMPLE".encode('ascii').ljust(20, b'\x00')
        # Job Number 1 (00 01)
        header += b'\x00\x01'
        # Summary (32 bytes)
        header += "Sample Job from PC".encode('ascii').ljust(32, b'\x00')

        # ---------------------------------------------------------
        # 2. Parameters (p97-98)
        # ---------------------------------------------------------
        # Number of parameters: 4
        params_count = b'\x00\x04'
        
        # P1: Global Params (Type 01) - p97
        # 18 bytes length (00 12)
        p1 = b'\x01\x00\x00\x12' 
        # Data: Normal dir, No Tacho, Object mode, mm, etc... (매뉴얼 값 참조)
        p1 += b'\x10\x02\x05\x00\x03\x00\x03\x00\x02\x01\x00\x00\x00'

        # P2: Barcode Params (Type 04) - p98
        # 30 bytes length (00 1E)
        p2 = b'\x04\x01\x00\x1E'
        # ID(17h DataMatrix), Type(01h 2D), Height(24), Quiet(10), etc...
        p2 += b'\x17\x01\x00\x0E\x00\x00\x18\x00\x0A\x01\x00\x00\x00\x00\x00\x00\x00\x06'
        # Motif data "REF 123" (Example)
        p2 += b'\x52\x45\x46\x31\x32\x33\x00\x00'

        # P3: Line Y Coordinates (Type 08) - p99
        # 14 bytes length (00 0E)
        p3 = b'\x08\x00\x00\x0E'
        # Line 1 Y=0, Line 2 Y=8, ... (매뉴얼 값)
        p3 += b'\x00\x00\x00\x08\x00\x10\x00\x18\x00\x1F'

        # P4: Number of Lines (Type 09) - p99
        # 4 bytes length (00 04)
        p4 = b'\x09\x02\x00\x04' # 2 Lines

        all_params = params_count + p1 + p2 + p3 + p4

        # ---------------------------------------------------------
        # 3. Lines Definition (p99-105)
        # ---------------------------------------------------------
        # --- Line 1 ---
        line1 = b'\x0A' # Delimiter
        
        # Block 1: Text "PRODUCT: " (Type 10)
        # 매뉴얼 p99 'Definition of first block' 참조
        b1_head = b'\x10\x00\x12\x01\x1E\x00\x00\x00\x01\x00\x01\x00\x00\x00\x00\x00\x12\x10'
        b1_text = "PRODUCT: ".encode('ascii') # p99 text def
        line1 += b1_head + b1_text

        # Block 2: Date (Type 1A) - p100 timestamp
        b2_date = b'\x1A\x00\x0E\x50\x51\x6E\x49\x4A\x6E\x55\x56\x00\x0E\x1A'
        line1 += b2_date

        # --- Line 2 ---
        line2 = b'\x0A' # Delimiter (p101)

        # Block 1: Text "MADE IN FRANCE" (Simplied)
        # 매뉴얼은 텍스트를 여러 블록으로 나누었으나 여기선 합침
        l2_b1_head = b'\x10\x00\x12\x01\x1B\x00\x00\x00\x01\x00\x01\x00\x00\x00\x00\x00\x12\x10'
        l2_b1_text = "MADE IN FRANCE ".encode('ascii')
        line2 += l2_b1_head + l2_b1_text

        # Block 2: External Variable (Type 12) - p101
        # Weight variable
        l2_b2_var = b'\x12\x00\x0B\x01\x78\x78\x78\x01\x00\x0B\x12' # Default 'xxx'
        line2 += l2_b2_var

        # Block 3: Text "KG"
        l2_b3_text = " KG".encode('ascii')
        # (헤더 생략하고 텍스트만 붙이는게 아니라 블록 헤더가 필요함. 간소화를 위해 텍스트만 추가되는 형태 가정)
        # *정석대로라면 Text 블록 헤더를 다시 붙여야 함*
        
        # End of Job Tag (p105)
        end_job = b'\x0D'

        # ---------------------------------------------------------
        # 4. Final Assembly (Header + Params + Lines + End)
        # ---------------------------------------------------------
        job_content = header + all_params + line1 + line2 + end_job
        
        # Total Length Calculation (4 bytes) - p97
        # 전체 길이에는 자기 자신(Total Length 필드 4바이트)도 포함됨
        total_len = len(job_content) + 8 # Total Len(4) + Checksum(4)
        total_len_bytes = total_len.to_bytes(4, byteorder='big')
        
        checksum_field = b'\x00\x00\x00\x00' # Checksum (Not used usually)

        full_file_data = total_len_bytes + checksum_field + job_content
        
        return full_file_data

# =============================================================================
# [LAYER 1] Controller Update
# =============================================================================
class PrinterController:
    def __init__(self, log_callback=None, status_callback=None):
        self.sock = None
        self.is_connected = False
        self.target_port = 2000
        self.log_callback = log_callback
        self.status_callback = status_callback

    def log(self, msg):
        if self.log_callback: self.log_callback(msg)

    def update_status(self, status, color):
        if self.status_callback: self.status_callback(status, color)

    def connect(self, ip_address):
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.settimeout(3.0)
            self.sock.connect((ip_address, self.target_port))
            self.is_connected = True
            self.log(f"✅ 접속 성공: {ip_address}")
            self.update_status("READY", "#2CC985")
            return True
        except Exception as e:
            self.is_connected = False
            self.log(f"❌ 접속 실패: {e}")
            self.update_status("ERROR", "#E74C3C")
            return False

    def disconnect(self):
        if self.sock: self.sock.close()
        self.is_connected = False
        self.update_status("DISCONNECTED", "#95a5a6")

    def _calculate_checksum(self, packet):
        checksum = 0
        for b in packet: checksum ^= b
        return checksum

    def send_9b_job(self):
        """매뉴얼 96p: Sending a job to the library (9Bh)"""
        if not self.is_connected:
            self.log("⛔ 프린터 미연결")
            return

        try:
            self.log("📦 샘플 Job 데이터 생성 중...")
            # 1. Job 데이터 생성 (JobBuilder 이용)
            job_data = JobBuilder.create_example_job_payload()
            
            # 2. ENQ
            self.sock.sendall(b'\x05')
            if self.sock.recv(1) != b'\x06':
                self.log("⛔ ENQ 응답 없음")
                return

            # 3. Packet Build (ID 9Bh)
            # 구조: [9B] [Len High] [Len Low] [JOB DATA...] [CS]
            identifier = 0x9B
            length = len(job_data)
            
            # Length는 2바이트 Big Endian
            len_bytes = length.to_bytes(2, byteorder='big')
            
            packet_content = bytes([identifier]) + len_bytes + job_data
            
            # Checksum
            checksum = self._calculate_checksum(packet_content)
            full_packet = packet_content + bytes([checksum])

            # 4. Send
            self.sock.sendall(full_packet)
            self.log(f"📤 Job 전송 (크기: {length} bytes)")

            # 5. Final ACK
            # 매뉴얼 29p: Response는 C5h (Report)가 옴
            resp_header = self.sock.recv(3) # ID(1) + Len(2)
            if not resp_header: return

            resp_id = resp_header[0]
            if resp_id == 0xC5: # 0xC5 = Response for 0x9B
                resp_len = int.from_bytes(resp_header[1:3], byteorder='big')
                resp_data = self.sock.recv(resp_len)
                self.sock.recv(1) # Checksum 읽기
                
                report = resp_data[0]
                if report == 0x00:
                    self.log("✅ Job 등록 성공 (Message Replaced)")
                elif report == 0x01:
                    self.log("✅ Job 등록 성공 (Message Created)")
                else:
                    self.log(f"⚠️ Job 등록 실패 (Code: {hex(report)})")
            elif resp_id == 0x15: # NACK
                 self.log("❌ 전송 실패 (NACK)")

        except Exception as e:
            self.log(f"💥 오류: {e}")
            self.disconnect()

# =============================================================================
# [LAYER 2] UI
# =============================================================================
class DashboardUI(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Markem-Imaje Job Loader")
        self.geometry("800x500")
        ctk.set_appearance_mode("Dark")
        
        self.controller = PrinterController(
            log_callback=self.add_log,
            status_callback=self.change_status
        )

        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        self.draw_sidebar()
        self.draw_main()

    def draw_sidebar(self):
        self.sidebar = ctk.CTkFrame(self, width=200, corner_radius=0)
        self.sidebar.grid(row=0, column=0, sticky="nsew")
        
        ctk.CTkLabel(self.sidebar, text="CONTROLLER", font=("Arial", 20, "bold")).pack(pady=30)
        
        self.ip_entry = ctk.CTkEntry(self.sidebar, placeholder_text="192.168.0.10")
        self.ip_entry.insert(0, "192.168.0.10")
        self.ip_entry.pack(pady=10, padx=20)
        
        self.btn_connect = ctk.CTkButton(self.sidebar, text="CONNECT", command=self.evt_connect)
        self.btn_connect.pack(pady=5, padx=20)

        ctk.CTkFrame(self.sidebar, height=2, fg_color="gray").pack(pady=20, fill="x", padx=10)

        # [NEW] 샘플 예제 전송 버튼
        self.btn_send_sample = ctk.CTkButton(
            self.sidebar, 
            text="SEND SAMPLE JOB\n(Manual p.96)", 
            fg_color="#8E44AD", 
            height=60,
            command=self.evt_send_sample
        )
        self.btn_send_sample.pack(pady=10, padx=20)

    def draw_main(self):
        self.main_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.main_frame.grid(row=0, column=1, sticky="nsew", padx=20, pady=20)
        
        self.lbl_status = ctk.CTkLabel(self.main_frame, text="DISCONNECTED", font=("Arial", 30, "bold"), text_color="gray")
        self.lbl_status.pack(pady=20)

        self.log_box = ctk.CTkTextbox(self.main_frame, height=300)
        self.log_box.pack(fill="both", expand=True)

    def evt_connect(self):
        if not self.controller.is_connected:
            threading.Thread(target=self.controller.connect, args=(self.ip_entry.get(),)).start()
        else:
            self.controller.disconnect()
            self.btn_connect.configure(text="CONNECT")

    def evt_send_sample(self):
        # 버튼 누르면 9Bh 명령 전송
        threading.Thread(target=self.controller.send_9b_job).start()

    def add_log(self, msg):
        self.log_box.insert("end", f"[{datetime.now().strftime('%H:%M:%S')}] {msg}\n")
        self.log_box.see("end")

    def change_status(self, text, color):
        self.lbl_status.configure(text=text, text_color=color)
        if text == "READY": self.btn_connect.configure(text="DISCONNECT", fg_color="gray")
        else: self.btn_connect.configure(text="CONNECT", fg_color="#2980B9")

if __name__ == "__main__":
    app = DashboardUI()
    app.mainloop()