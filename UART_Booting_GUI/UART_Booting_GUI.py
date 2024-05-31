import serial
import threading
import sys
import time
import os
import tkinter as tk
from tkinter import filedialog, scrolledtext, ttk
import serial.tools.list_ports  # 시리얼 포트 목록 가져오기
import base64
import re
import ctypes

# XMODEM 패킷의 데이터 크기
PACKET_SIZE = 128

# XMODEM 프로토콜에서 사용하는 특수한 문자
SOH = 0x01  # 패킷 헤더 시작 바이트
EOT = 0x04  # 파일 전송 종료 바이트
ACK = 0x06  # 패킷 수신 확인 바이트
NAK = 0x15  # 패킷 수신 거부 바이트
CAN = 0x18  # 취소 바이트
CPMEOF = 0x1A  # 마지막 패킷의 크기를 맞추기 위해 사용되는 바이트(마지막 패킷일 경우 CPMEOF(0x1A)로 패딩)

# 플래그 설정 -> threading.Event 객체를 사용하여 스레드를 종료하기 위한 플래그를 설정
stop_thread = threading.Event()

# 선택한 파일의 정보를 저장하기 위한 리스트. 각 항목은 선택한 파일의 경로와 해당 파일을 전송했는지 여부를 포함하는 딕셔너리
file_info_list = []

# 파일 경로를 저장하는 리스트. 파일 선택 버튼을 누를 때마다 각 파일의 경로를 저장
file_dialog = [None] * 6

# send_button default 값
send_button_clicked = False

# console 창 유무 defualt 값
console_window = None

# 연결 가능한 Port 갱신하기 위한 리스트
previous_ports = []

# 파일 경로의 기본 텍스트 목록
file_dialog_default_texts = ["Please select the configuration file",
                             "Please select the binary0 file",
                             "Please select the binary1 file",
                             "Please select the binary2 file",
                             "Please select the binary3 file",
                             "Please select the binary4 file"]


class RedirectText:
    def __init__(self, widget):
        self.widget = widget
        # 위젯이 자동으로 스크롤될지 여부를 제어
        self.auto_scroll = True

    def write(self, string):
        #  string을 위젯 내용의 끝에 삽입
        self.widget.insert(tk.END, string)

        # 만약 스크롤이 활성화 되었다면 텍스트의 끝이 보이도록 함
        if self.auto_scroll:
            self.widget.see(tk.END)

    def flush(self):
        pass

    def toggle_auto_scroll(self, event):
        if self.widget and self.widget.winfo_exists():  # 위젯이 존재하는지 확인
            # 사용자가 맨 아래까지 스크롤했다는 것을 의미
            if self.widget.yview()[1] == 1.0:
                self.auto_scroll = True
            else:
                self.auto_scroll = False

    def clear(self):
        # 위젯 내용 지우기
        self.widget.delete(1.0, tk.END)


# 연결 가능한 직렬 Port 목록 검색 함수
def scan_ports():
    ports = [port.device for port in serial.tools.list_ports.comports()]
    return ports


# Serial 연결 함수
def connect_serial():
    global ser

    port = port_var.get()
    baudrate = baud_var.get()

    try:
        ser = serial.Serial(
            port=port,
            baudrate=int(baudrate),
            parity=serial.PARITY_NONE,  # 패리티 비활성화
            stopbits=serial.STOPBITS_ONE,  # 1개의 정지 비트 설정
            bytesize=serial.EIGHTBITS,  # 데이터 비트 설정 (8비트 사용)
            timeout=None,  # 논블로킹 모드
            rtscts=False,  # RTS/CTS 흐름 제어 비활성화
            dsrdtr=False,  # DSR/DTR 흐름 제어 비활성화
            xonxoff=False  # XON/XOFF 흐름 제어 비활성화
        )

        # 콘솔창이 있을 때만 출력
        if console_window:
            print(f"Connected to {port} at {baudrate} baud.")

        # 플래그를 재설정하여 스레드를 다시 시작할 수 있게 함
        stop_thread.clear()

        # 수신 스레드 시작
        thread = threading.Thread(target=read_from_port, args=(ser, stop_thread))
        thread.daemon = True
        thread.start()

        if port:
            # 연결 정보 라벨 업데이트
            connect_label.config(text=f"Connected to Port: {port} | Baudrate: {baudrate}")
        else:
            # If no port is selected, display an error message
            connect_label.config(text="No port selected!")
    except Exception as e:
        if console_window:
            print(f"Could not connect to {port} at {baudrate} baud: {e}")


# Serial 연결 끊기 함수
def disconnect_serial():
    global ser

    if ser and ser.is_open:
        stop_thread.set()  # 스레드 중지
        ser.close()
        if console_window:
            print("Disconnected from the serial port.")
        # 연결 상태를 나타내는 라벨 텍스트 업데이트
        connect_label.config(text="Disconnected")


# 콘솔창 함수
def create_console_window():
    global console_window
    global write_text_label
    global console_text

    # 이미 콘솔 창이 열려있는 경우
    if console_window and console_window.winfo_exists():
        # 이미 존재하는 창을 활성화
        console_window.deiconify()
        return

    # 새로운 창을 생성
    console_window = tk.Toplevel()
    console_window.title("Console Output")
    console_window.geometry("800x600")

    # 콘솔 텍스트의 글자 폰트와 크기 설정
    console_text = scrolledtext.ScrolledText(console_window, wrap=tk.WORD, font=("Consolas", 10))
    console_text.pack(fill=tk.BOTH, expand=True)

    # 마우스 휠을 사용하여 스크롤할 때 sys.stdout의 toggle_auto_scroll 메서드 호출
    console_text.bind("<MouseWheel>", lambda event: sys.stdout.toggle_auto_scroll(event))
    # 키보드를 사용하여 스크롤할 때 sys.stdout의 toggle_auto_scroll 메서드 호출
    console_text.bind("<KeyPress>", lambda event: sys.stdout.toggle_auto_scroll(event))

    # 콘솔 출력을 콘솔 텍스트 위젯으로 리디렉션
    # 리디렉션(원래 표준 출력 또는 표준 오류 스트림으로 사용되던 객체(sys.stdout 및 sys.stderr)를 다른 객체로 대체하여,
    # 출력이 원래 목적지(예: 터미널, 콘솔) 대신 다른 곳으로 보내지도록 하는 것을 의미)
    sys.stdout = RedirectText(console_text)
    sys.stderr = RedirectText(console_text)

    # write할 text 프레임
    write_text_frame = ttk.LabelFrame(console_window, text="Text")
    write_text_frame.pack(pady=5)

    write_text_label = tk.Text(write_text_frame, width=80, height=1)
    write_text_label.pack(pady=5, fill=tk.BOTH, expand=True)
    write_text_label.bind('<Return>', send_text)  # Enter 키 바인딩 추가

    # Text 보내기 버튼
    send_text_button = tk.Button(write_text_frame, text="Send text", command=send_text, width=30, height=3)
    send_text_button.pack(side=tk.LEFT, pady=5, expand=True)

    # Console Clear 버튼
    console_clear_button = tk.Button(write_text_frame, text="Clear", command=console_clear, width=30, height=3)
    console_clear_button.pack(side=tk.LEFT, pady=5, expand=True)

    # 콘솔 창이 닫힐 때 호출되는 함수를 지정
    console_window.protocol("WM_DELETE_WINDOW", close_console_window)


# 콘솔 창 닫기 함수
def close_console_window():
    global console_window
    if console_window:
        console_window.destroy()
        console_window = None
        # 콘솔 창이 닫힐 때 표준 출력 스트림으로 다시 설정
        sys.stdout = sys.__stdout__
        sys.stderr = sys.__stderr__


# 콘솔 텍스트 지우기
def console_clear():
    if console_window:
        sys.stdout.clear()
        sys.stderr.clear()


def send_text(event=None):
    # global ser
    if ser and ser.is_open:
        text_to_send = write_text_label.get("1.0", tk.END).strip()  # 텍스트 위젯에서 텍스트 가져오기
        if text_to_send:
            try:
                text_to_send += '\n'  # 명령어 끝에 새 줄 문자 추가
                ser.write(text_to_send.encode('utf-8'))  # 텍스트를 UTF-8 인코딩으로 시리얼 포트를 통해 송신
                ser.flush()  # 시리얼 포트를 플러싱
                write_text_label.delete("1.0", tk.END)  # 텍스트 위젯의 내용을 지우기
                # 출력 후 자동 스크롤
                sys.stdout.auto_scroll = True
            except Exception as e:
                if console_window:
                    print(f"Failed to send text: {e}")
        else:
            if console_window:
                print("No text to send.")
    else:
        if console_window:
            print("Serial port is not open.")

    return "break"


# Xmodem 프로토코를 사용해서 파일 전송
def send_file(ser, filename):
    global send_button_clicked

    try:
        with open(filename, "rb") as file:
            packet = bytearray(PACKET_SIZE + 5)  # 패킷 버퍼
            sequence = 1  # 패킷 시퀀스 번호
            retries = 10  # 재시도 횟수

            file.seek(0, os.SEEK_END)  # 파일 끝으로 이동
            file_size = file.tell()  # 파일 크기 확인
            file.seek(0, os.SEEK_SET)  # 파일 시작으로 이동

            bytes_sent = 0  # 전송된 바이트 수

            # 박스의 전체 개수
            total_boxes = 10
            # 파일 크기에 따른 한 박스당 크기
            box_size = file_size / total_boxes

            # 진행률이 마지막으로 업데이트된 박스의 인덱스
            last_box_index = -1

            if console_window:
                sys.stdout.write("\n진행률: ")

            progress_label.config(text="진행률: ")

            while True:
                # 패킷 생성
                packet[0] = SOH
                packet[1] = sequence
                packet[2] = 0xFF - sequence

                # 파일에서 데이터를 읽어 패킷에 저장
                count = file.read(PACKET_SIZE)

                if not count:  # 파일의 끝에 도달했을 때
                    break

                if len(count) < PACKET_SIZE:
                    # 마지막 패킷일 경우 CPMEOF(0x1A)로 패딩
                    count += bytes([CPMEOF] * (PACKET_SIZE - len(count)))

                packet[3:3 + PACKET_SIZE] = count

                # CRC 계산 및 패킷에 추가
                crc = calculate_crc(packet[3:3 + PACKET_SIZE])
                packet[3 + PACKET_SIZE] = (crc >> 8) & 0xFF
                packet[4 + PACKET_SIZE] = crc & 0xFF

                # 패킷 전송 및 ACK 수신 확인
                while retries > 0:
                    ser.write(packet)  # 패킷 전송
                    time.sleep(0.01)  # 잠시 대기

                    # ACK 수신 확인
                    ack = ser.read(1)
                    if ack == bytes([ACK]):
                        sequence = (sequence + 1) % 256  # 다음 시퀀스 번호로 업데이트
                        retries = 10  # 재시도 횟수 초기화
                        time.sleep(0.01)
                        break
                    else:
                        retries -= 1  # 재시도 횟수 감소

                if not send_button_clicked:
                    ser.write(bytes([EOT]))
                    if console_window:
                        print("send_button_clicked이 False로 되어있습니다.")
                    return False

                if retries == 0:
                    print("파일 전송 실패")
                    return False  # 실패

                # 전송된 바이트 수 업데이트
                bytes_sent += len(count)

                # 현재 진행 상태 계산
                current_progress = int(bytes_sent / box_size)

                if console_window:
                    # 진행 상태가 업데이트되었을 때만 출력
                    if current_progress != last_box_index:
                        # 진행 상태 업데이트
                        last_box_index = current_progress
                        # 진행률 표시
                        sys.stdout.write('█')
                        sys.stdout.flush()

                # progress_label 업데이트
                progress_bar = '█' * current_progress
                progress_label.config(text=f"진행률: {progress_bar}")

            # 파일 전송이 완료되면 EOT를 전송하여 종료를 알림
            ser.write(bytes([EOT]))
            if console_window:
                print("\n파일 전송이 완료되었습니다.")
            return True  # 성공
    except Exception as e:
        print(f"Error: {e}")
        return False


# CRC 계산(XMODEM 프로토콜)
def calculate_crc(data):
    crc = 0
    for byte in data:
        crc ^= byte << 8
        for _ in range(8):
            if crc & 0x8000:
                crc = (crc << 1) ^ 0x1021
            else:
                crc <<= 1
    return crc & 0xFFFF


# 파일 전송 성공시 라벨 변경
def send_file_button(filename):
    if filename:
        success = send_file(ser, filename)
        if success:
            send_success_label.config(text=f"{filename} sent successfully.")
        else:
            send_success_label.config(text=f"{filename} send failed.")


# 체크박스 상태에 따라 파일 선택 버튼의 상태 업데이트
def update_button_state(idx):
    if checkboxes[idx].get():  # 체크박스가 선택되었을 때
        file_buttons[idx].config(state=tk.NORMAL)
    else:
        file_buttons[idx].config(state=tk.DISABLED)
        file_path_labels[idx].config(state=tk.NORMAL)
        file_path_labels[idx].delete(0, tk.END)
        file_path_labels[idx].insert(0, file_dialog_default_texts[idx])
        file_path_labels[idx].config(state='readonly')
        file_size_labels[idx].config(state='readonly')


# 파일 선택 버튼(폴더 모양 버튼)을 눌렀을 때 호출되는 함수
def selected_file(idx, file_path_labels, file_size_labels):
    # 선택한 파일의 경로를 filename 변수에 저장
    filename = filedialog.askopenfilename()

    if filename:
        file_dialog[idx] = filename  # 파일 경로 저장
        file_info_list.append({'filename': filename, 'sent': False})  # 파일 정보 저장
        file_path_labels[idx].config(state=tk.NORMAL)
        file_path_labels[idx].delete(0, tk.END)
        file_path_labels[idx].insert(0, filename)
        file_path_labels[idx].config(state='readonly')

        file_size_labels[idx].config(state=tk.NORMAL)
        file_size_labels[idx].delete(0, tk.END)
        file_size_labels[idx].insert(0, f"{os.path.getsize(filename)} bytes")
        file_size_labels[idx].config(state='readonly')
        send_success_label.update()  # 업데이트하여 화면에 표시되도록 함


# send 버튼 클릭 시 동작하는 함수
def send_true():
    global send_button_clicked
    send_button_clicked = True
    send_label.config(text="send_button = " + str(send_button_clicked))
    if console_window:
        print("\nsend_button = True")


# stop 버튼 클릭 시 동작하는 함수
def send_false():
    global send_button_clicked
    send_button_clicked = False
    send_label.config(text="send_button = " + str(send_button_clicked))
    sending_label.config(text="")
    send_success_label.config(text="")
    progress_label.config(text="")

    if console_window:
        print("\nsend_button = False")


# ansi escape sequences 처리 함수
def cut_ansi_string_into_parts(string_with_ansi_codes):
    color_codes_english = ['Black', 'Red', 'Green', 'Yellow', 'Blue', 'Magenta', 'Cyan', 'White', 'Green', 'Green']
    color_codes = ["30", "31", "32", "33", "34", "35", "36", "37", "94", "92"]
    effect_codes_english = ['Italic', 'Underline', 'Slow Blink', 'Rapid Blink', 'Crossed Out']
    effect_codes = ["3", "4", "5", "6", "9"]
    background_codes = ["40", "41", "42", "43", "44", "45", "46", "47"]
    background_codes_english = ["Black", "Red", "Green", "Yellow", "Blue", "Magenta", "Cyan", "White"]

    tuple_list = []

    # Split string by ANSI escape sequences
    string_list = re.split(r'(\x1B\[[0-9;]*m)', string_with_ansi_codes)

    current_color = None
    current_effect = None
    current_background = None

    for segment in string_list:
        if segment.startswith('\x1B[') and segment.endswith('m'):
            codes = segment[2:-1].split(';')
            for code in codes:
                if code in color_codes:
                    current_color = color_codes_english[color_codes.index(code)]
                elif code in effect_codes:
                    current_effect = effect_codes_english[effect_codes.index(code)]
                elif code in background_codes:
                    current_background = background_codes_english[background_codes.index(code)]
                elif code == "0":
                    current_color = None
                    current_effect = None
                    current_background = None
        else:
            if segment:
                tuple_list.append((segment, current_color, current_background, current_effect))

    return tuple_list


def read_from_port(ser, stop_event):
    buffer = ""

    def apply_color_to_text(text, color):
        console_text.tag_configure(color, foreground=color)
        console_text.insert(tk.END, text, color)

    def read_and_process():
        nonlocal buffer

        if stop_event.is_set():
            return

        if ser.in_waiting > 0:
            data = ser.read(ser.in_waiting).decode('utf-8', errors='ignore')
            buffer += data

            # '\x1b'는 ASCII 코드에서 "ESC" (Escape) 키
            if '\x1b' in buffer:
                parts = cut_ansi_string_into_parts(buffer)
                for part in parts:
                    text, color, _, _ = part
                    if color:
                        apply_color_to_text(text, color.lower())
                    else:
                        apply_color_to_text(text, 'black')
                print("", end="")
                buffer = ""
            else:
                print(buffer, end="")
                buffer = ""

            check_conditions(data)

        # 타이머 0.1초
        threading.Timer(0.1, read_and_process).start()

    read_and_process()


# 전송할 파일 선택 함수
def check_conditions(data):
    global send_button_clicked

    if "Please send the configuration file to XMODEM" in data and send_button_clicked:
        sending_label.config(text="configuration sending")
        send_file_button(file_dialog[0])
    elif "Please send the binary1 to XMODEM" in data and send_button_clicked:
        sending_label.config(text="binary1 sending")
        send_file_button(file_dialog[2])
    elif "Please send the binary3 to XMODEM" in data and send_button_clicked:
        sending_label.config(text="binary3 sending")
        send_file_button(file_dialog[4])


# # 종료 함수
# def exit_program():
#     stop_thread.set()  # 플래그 설정
#     try:
#         if ser and ser.is_open:
#             ser.close()
#     except NameError:  # ser가 정의되지 않은 경우에 대한 예외 처리
#         pass
#     sys.exit(0)  # 프로그램 종료


def main():
    # 라벨 전역 변수 선언
    global connect_label, write_text_label, send_label, send_success_label, sending_label, progress_label

    global port_var, baud_var, file_buttons, \
        checkboxes, file_path_labels, file_size_labels, \
        send_button_clicked, console_window, previous_ports

    # GUI 생성
    root = tk.Tk()
    root.title("EN677 UART booting")
    root.geometry("740x620")
    root.resizable(width=False, height=False)

    icon_image64 = """
    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
    """

    folder_image64 = """iVBORw0KGgoAAAANSUhEUgAAABkAAAAZCAYAAADE6YVj
    AAAB7UlEQVR4nN2Vz2pTQRSHv3Pu3IREjU0JIgVFQZd1J+4EF9aNUDeKFHwDfQIfRN
    wIoqDUjZSK1IXgS7hNC2laFZNg09TeOzPHRSt0kTT9cwviDwaG4XfONzNnmAP/i+TvZPX
    53epUw08Ohph+Z1GCF3/u0dLakSHd+duXkyjvVbkUog01lpyGzNuzsw8/PT0sRAHMc/NMxV0zpKaq
    QwdIXYTHgzczFw4LcQDRTPNgxBGnAMii4RKpZdE+9N7OfAbCqF0niZL58HXifPZSbn3xDiBRGZ19j3wwSqlMp4
    lO7+cToOQcv9ZpAx8dgI8xBwMbz8pzI8/jWF+17AjBNwBcb3GuXoqDGyJGwvjgAytVqrXy9d7i3KKrpOFFqXz
    qXpZF0nJxjAiUU30SB9sXncHV6OOBrurQIB8RuKKCNFVkfMQRJAIYTQVpcjIMdhi2rBbj8skgwDBUrKmIrYRQfD0
    AQjACrGjw2vIh+qLLIgK5jx6TlkpF10XYkIIpO/msn+X+m25u9DsY3aJfmAqo0JkQ+6mN2YU+It9VC2WgIpjxg9mF
    vopgmK1ReFEArC2Cud2FFqmivsC/ywlmrMJuP/EWX+vm9p0YmdqvpxxUqpAH2mb6Cvb0eJu/f5o6k1tbx2ZQqQBdOvLg
    Xf/42f4l/QG7itCC23oQnAAAAABJRU5ErkJggg=="""

    # 베이스64 데이터를 바이너리 데이터로 변환
    photo_data = base64.b64decode(folder_image64)

    # PhotoImage 객체 생성
    image = tk.PhotoImage(data=photo_data)

    icon32 = tk.PhotoImage(data=icon_image64)

    root.iconphoto(False, icon32)

    # 이전에 발견된 포트 목록을 저장하기 위한 변수
    def update_ports():
        global previous_ports
        current_ports = scan_ports()

        # 이전에 발견된 포트와 현재 발견된 포트를 비교하여 새로운 포트와 사라진 포트를 찾음
        new_ports = [port for port in current_ports if port not in previous_ports]
        removed_ports = [port for port in previous_ports if port not in current_ports]

        # 새로운 포트가 있을 경우, 해당 포트를 콤보박스에 추가
        port_menu['values'] = current_ports

        # 사라진 포트가 있을 경우, 해당 포트를 콤보박스에서 제거
        for port in removed_ports:
            if port_var.get() == port:  # 현재 선택된 포트가 사라진 경우
                port_var.set('')  # 선택 해제
            if port in current_ports:
                current_ports.remove(port)  # 현재 포트 목록에서 삭제
        previous_ports = current_ports  # 현재 발견된 포트 목록을 이전 포트 목록으로 업데이트

        # 일정 시간 간격마다 다시 포트를 업데이트하도록 설정
        root.after(1000, update_ports)

    # Serial connection frame
    connection_frame = tk.LabelFrame(root, text="Serial Connection")
    connection_frame.grid(row=0, column=0, padx=10, pady=10, sticky="nsew")

    # Port selection
    tk.Label(connection_frame, text="Port:").grid(row=0, column=0, padx=5, pady=5)
    port_var = tk.StringVar()
    port_menu = ttk.Combobox(connection_frame, textvariable=port_var)
    port_menu['values'] = [port.device for port in serial.tools.list_ports.comports()]
    port_menu.grid(row=0, column=1, padx=5, pady=5)

    # Baudrate selection
    tk.Label(connection_frame, text="Baudrate:").grid(row=0, column=2, padx=5, pady=5)
    baud_var = tk.StringVar(value="115200")
    baud_menu = ttk.Combobox(connection_frame, textvariable=baud_var)
    baud_menu['values'] = ["2400", "4800", "9600", "19200", "38400", "57600", "115200", "230400", "460800", "921600"]
    baud_menu.grid(row=0, column=3, padx=5, pady=5)

    # Connect and Disconnect buttons
    connect_button = tk.Button(connection_frame, text="Connect", command=connect_serial)
    connect_button.grid(row=0, column=4, padx=5, pady=5)
    disconnect_button = tk.Button(connection_frame, text="Disconnect", command=disconnect_serial)
    disconnect_button.grid(row=0, column=5, padx=5, pady=5)

    # 전송 상태를 나타내는 라벨
    connect_label = tk.Label(connection_frame, text="Disconnected")
    connect_label.grid(row=1, column=0, columnspan=6, padx=5, pady=5)

    # Console output
    console_button = tk.Button(connection_frame, text="Open Console", command=lambda: create_console_window(), height=3)
    console_button.grid(row=0, column=6, padx=15, pady=5)

    ### Send 프레임
    send_frame = ttk.LabelFrame(root, text="Send Settings")
    send_frame.grid(row=1, column=0, padx=10, pady=10, sticky="nsew")

    # 파일 선택 관련 위젯 배치
    file_buttons = []  # 파일 선택 버튼 리스트
    checkboxes = []
    file_path_labels = []
    file_size_labels = []

    for i in range(6):
        file_frame = tk.Frame(send_frame)
        file_frame.pack(padx=10, pady=5, fill="x")

        file_checkbox_var = tk.BooleanVar()
        file_checkbox = tk.Checkbutton(file_frame, text="", variable=file_checkbox_var,
                                       command=lambda idx=i: update_button_state(idx))
        file_checkbox.pack(side="left", pady=2)
        checkboxes.append(file_checkbox_var)

        file_button = tk.Button(file_frame,
                                text="Select File",
                                command=lambda idx=i: selected_file(idx, file_path_labels, file_size_labels),
                                image=image,
                                state=tk.DISABLED)
        file_button.pack(side="left", padx=10)
        file_buttons.append(file_button)

        file_path_label = tk.Entry(file_frame, width=50)
        file_path_label.pack(side="left", padx=10, fill="x", expand=True)
        file_path_label.insert(0, file_dialog_default_texts[i])
        file_path_label.config(state='readonly')
        file_path_labels.append(file_path_label)

        file_size_label = tk.Entry(file_frame, text="", width=20, state='readonly')
        file_size_label.pack(side="left", padx=10)
        file_size_labels.append(file_size_label)

    # send_button 상태 라벨
    send_label = tk.Label(send_frame, text="")
    send_label.pack(pady=5)

    # Send 및 Stop 버튼
    send_button_frame = tk.Frame(send_frame)
    send_button_frame.pack(fill="x", padx=5, pady=5)

    # Send 버튼
    send_button = tk.Button(send_button_frame, text="Send", command=send_true, width=15)
    send_button.pack(side="left", padx=5, expand=True)

    # Stop 버튼
    stop_button = tk.Button(send_button_frame, text="Stop", command=send_false, width=15)
    stop_button.pack(side="left", padx=5, expand=True)

    ### 상태 프레임
    status_frame = ttk.LabelFrame(root, text="Status")
    status_frame.grid(row=2, column=0, padx=10, pady=10, sticky="nsew")

    # 전송 중인 파일명 라벨
    sending_label = tk.Label(status_frame, text="")
    sending_label.pack(pady=5)

    # 전송 진행률 표시 라벨
    progress_label = tk.Label(status_frame, text="")
    progress_label.pack(pady=5)

    # 전송 완료 파일 라벨
    send_success_label = tk.Label(status_frame, text="")
    send_success_label.pack(pady=5)

    # Tkinter 앱을 생성하고 초기 포트를 업데이트합니다.
    update_ports()

    root.mainloop()


if __name__ == "__main__":
    main()

