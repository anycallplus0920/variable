import streamlit as st
import socket
import time
import pandas as pd
from datetime import datetime
import os

# =============================================================================
# [LAYER 0] 프로토콜 & 유틸리티
# =============================================================================
def calculate_checksum(packet):
    checksum = 0
    for b in packet:
        checksum ^= b
    return checksum

def construct_e8_command(data_str):
    """0xE8: 가변 데이터 전송 패킷 생성"""
    command = bytearray([0xE8])
    command.extend([0x00, 0x00]) # Length 자리

    variable_id = 0x01
    variable_data = str(data_str).encode('ascii') 
    variable_length = len(variable_data)

    command.append(variable_id)
    command.extend([(variable_length >> 8) & 0xFF, variable_length & 0xFF])
    command.extend(variable_data)

    data_length = len(command) - 3
    command[1] = (data_length >> 8) & 0xFF
    command[2] = data_length & 0xFF

    checksum = calculate_checksum(command)
    command.append(checksum)
    
    return command

def save_log(sent_count, data_val):
    """로컬 파일에 로그 저장"""
    date_str = datetime.now().strftime("%Y%m%d")
    filename = f"PrintLog_{date_str}.txt"
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    with open(filename, "a", encoding="utf-8") as f:
        f.write(f"{sent_count} - {data_val} - {timestamp}\n")

# =============================================================================
# [LAYER 1] Streamlit UI & Logic
# =============================================================================

st.set_page_config(page_title="KOCA Printer System", layout="wide", page_icon="🖨️")

if 'sent_count' not in st.session_state:
    st.session_state.sent_count = 0
if 'logs' not in st.session_state:
    st.session_state.logs = []
if 'excel_df' not in st.session_state:
    st.session_state.excel_df = None

# --- 사이드바 ---
with st.sidebar:
    st.header("⚙️ 연결 설정")
    ip_address = st.text_input("IP Address", "192.168.0.10")
    port = st.number_input("Port", value=2000)
    
    st.divider()
    
    st.header("📂 데이터 로드")
    uploaded_file = st.file_uploader("엑셀 파일 업로드", type=["xlsx"])
    
    if uploaded_file is not None:
        try:
            df = pd.read_excel(uploaded_file, dtype=str)
            flat_data = []
            for col in df.columns:
                flat_data.extend(df[col].dropna().tolist())
            
            st.session_state.excel_df = flat_data
            st.success(f"로드 완료: {len(flat_data)}개 데이터")
        except Exception as e:
            st.error(f"엑셀 오류: {e}")

# --- 메인 화면 ---
st.title("🖨️ 자동 가변 데이터 인쇄 시스템")
st.markdown("### Auto Variable Data Printing System (TCP/IP)")

col1, col2, col3, col4 = st.columns(4)
col1.metric("Target IP", f"{ip_address}")
col2.metric("Total Sent", f"{st.session_state.sent_count} ea")

data_remaining = len(st.session_state.excel_df) if st.session_state.excel_df else 0
col3.metric("Remaining Data", f"{data_remaining} ea")

status_placeholder = col4.empty()
status_placeholder.metric("System Status", "IDLE")

st.divider()

# --- 실행 제어 ---
c_btn1, c_btn2 = st.columns([1, 4])

if c_btn1.button("▶ START PRODUCTION", type="primary", use_container_width=True):
    
    if not st.session_state.excel_df or len(st.session_state.excel_df) == 0:
        st.error("전송할 데이터가 없습니다. 엑셀 파일을 업로드하세요.")
    else:
        status_placeholder.metric("System Status", "CONNECTING...", delta_color="off")
        
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(5.0)
                s.connect((ip_address, port))
                
                init_packet = bytes([0x41, 0x00, 0x01, 0x01, 0x41])
                s.send(init_packet)
                
                st.toast("✅ 프린터 연결 성공! 생산을 시작합니다.")
                
                progress_bar = st.progress(0)
                work_list = list(st.session_state.excel_df)
                log_area = st.empty()
                
                while len(work_list) > 0:
                    current_data = work_list[0]
                    
                    status_placeholder.metric("System Status", "PRINTING...", delta_color="inverse")
                    log_area.info(f"📤 전송 중: **{current_data}** (0xE7 대기 중...)")
                    
                    s.sendall(b'\x05')
                    packet = construct_e8_command(current_data)
                    s.sendall(packet)
                    
                    response_received = False
                    start_wait = time.time()
                    
                    while True:
                        try:
                            resp = s.recv(1)
                            if not resp: break
                            
                            if resp == b'\xe7':
                                response_received = True
                                break
                            
                            if time.time() - start_wait > 60:
                                st.error("⏰ 인쇄 타임아웃! (60초 경과)")
                                break
                                
                        except socket.timeout:
                            continue
                        except Exception as e:
                            st.error(f"통신 에러: {e}")
                            break
                    
                    if response_received:
                        st.session_state.sent_count += 1
                        save_log(st.session_state.sent_count, current_data)
                        
                        work_list.pop(0)
                        st.session_state.excel_df = work_list
                        
                        current_progress = st.session_state.sent_count / (st.session_state.sent_count + len(work_list))
                        progress_bar.progress(min(current_progress, 1.0))
                        
                        time.sleep(0.1)
                    else:
                        st.error("❌ 인쇄 실패 또는 중단")
                        break
                
                if len(work_list) == 0:
                    status_placeholder.metric("System Status", "COMPLETED", delta_color="normal")
                    st.success("🎉 모든 작업이 완료되었습니다!")
                    st.balloons()
                
        except Exception as e:
            st.error(f"연결 실패 (내부망 접속 불가): {e}")
            status_placeholder.metric("System Status", "ERROR", delta_color="inverse")

# --- 로그 ---
with st.expander("📝 최근 작업 로그 (Local File)", expanded=True):
    date_str = datetime.now().strftime("%Y%m%d")
    filename = f"PrintLog_{date_str}.txt"
    if os.path.exists(filename):
        with open(filename, "r", encoding="utf-8") as f:
            lines = f.readlines()
            st.code("".join(lines[-10:]))
    else:
        st.write("아직 로그가 없습니다.")
