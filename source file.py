import socket
import argparse
import sys
import os
from struct import pack
import random

# --- 설정 및 상수 정의 ---
# TFTP 기본 포트는 69번입니다.
DEFAULT_PORT = 69
# TFTP 데이터 블록의 크기는 512 바이트입니다.
BLOCK_SIZE = 512
# 전송 모드는 'octet' (바이너리) 모드를 기본으로 사용합니다.
DEFAULT_TRANSFER_MODE = 'octet'
# 소켓 타임아웃 시간 (초)
TIME_OUT = 3.0
# 최대 재전송 시도 횟수
MAX_TRY = 5

# --- Opcode 정의 ---
# TFTP 패킷의 종류를 식별하는 코드입니다.
OPCODE = {'RRQ': 1, 'WRQ': 2, 'DATA': 3, 'ACK': 4, 'ERROR': 5}

# --- 에러 코드 정의 ---
# TFTP 에러 패킷에 포함되는 오류 코드와 메시지입니다.
ERROR_CODE = {
    0: "Not defined, see error message (if any).",
    1: "File not found.",
    2: "Access violation.",
    3: "Disk full or allocation exceeded.",
    4: "Illegal TFTP operation.",
    5: "Unknown transfer ID.",
    6: "File already exists.",
    7: "No such user."
}


def create_request_packet(opcode_type, filename, mode):
    """
    RRQ (Read Request) 또는 WRQ (Write Request) 패킷을 생성합니다.
    구조: Opcode(2byte) + Filename(string) + 0(1byte) + Mode(string) + 0(1byte)
    """
    # struct.pack을 사용하여 바이너리 데이터로 포장합니다.
    # >: 빅엔디안, h: short(2byte), s: string(bytes), B: unsigned char(1byte)
    format_str = f'>h{len(filename)}sB{len(mode)}sB'
    return pack(format_str, OPCODE[opcode_type], bytes(filename, 'utf-8'),
                0, bytes(mode, 'utf-8'), 0)


def send_ack(sock, seq_num, server_address):
    """
    ACK (Acknowledgement) 패킷을 생성하고 서버로 전송합니다.
    구조: Opcode(2byte, ACK=4) + Block Number(2byte)
    """
    format_str = f'>hh'
    ack_message = pack(format_str, OPCODE['ACK'], seq_num)
    sock.sendto(ack_message, server_address)


def handle_error(data):
    """
    수신된 ERROR 패킷을 파싱하고 사용자에게 오류 메시지를 출력합니다.
    구조: Opcode(2byte, ERROR=5) + ErrorCode(2byte) + ErrMsg(string) + 0(1byte)
    """
    error_code = int.from_bytes(data[2:4], byteorder='big')
    # 에러 메시지는 4번째 바이트부터 마지막 널 바이트 전까지입니다.
    error_message = data[4:-1].decode('utf-8')
    print(f'🔥 TFTP 오류 발생: 에러 코드 {error_code}')
    print(f'   메시지: {error_message}')

    # 특정 에러 코드에 대한 추가 안내 메시지
    if error_code == 1:
        print("   -> File not found 오류입니다.")
    elif error_code == 6:
        print("   -> File already exists 오류입니다.")


def tftp_get(sock, filename, server_address):
    """
    TFTP 'get' (다운로드) 작업을 수행합니다.
    1. 서버에 RRQ 패킷 전송
    2. 데이터 수신 대기 및 ACK 전송 반복
    """
    print(f"⬇️ 파일 다운로드 요청: {filename}")

    # RRQ 패킷 생성
    request_packet = create_request_packet('RRQ', filename, DEFAULT_TRANSFER_MODE)

    # --- RRQ 전송 및 첫 데이터 패킷 수신 대기 (재시도 로직 포함) ---
    server_tid = server_address
    retries = 0
    while retries < MAX_TRY:
        try:
            sock.sendto(request_packet, server_tid)
            # 첫 번째 데이터 패킷(또는 에러) 수신.
            # 여기서 server_tid가 업데이트됩니다 (서버가 임의의 포트로 응답함).
            data, server_tid = sock.recvfrom(BLOCK_SIZE + 4)
            break
        except socket.timeout:
            retries += 1
            if retries == MAX_TRY:
                # 최대 재시도 횟수 초과 시 종료
                print("🚫 서버 응답이 없습니다. TFTP 다운로드 실패.")
                sys.exit()

    # --- 데이터 수신 및 ACK 전송 루프 ---
    expected_block_number = 1

    with open(filename, 'wb') as file:
        while True:
            # 수신된 패킷의 Opcode 확인
            # (첫 번째 루프에서는 위에서 이미 data를 받았으므로 바로 처리,
            #  두 번째 루프부터는 아래 try-except 블록에서 data를 받음)
            opcode = int.from_bytes(data[:2], 'big')

            if opcode == OPCODE['ERROR']:
                handle_error(data)
                break

            if opcode == OPCODE['DATA']:
                block_number = int.from_bytes(data[2:4], 'big')
                file_block = data[4:]

                # 예상한 블록 번호인지 확인
                if block_number == expected_block_number:
                    # 정상 순서의 데이터: 파일에 쓰고 ACK 전송
                    file.write(file_block)
                    send_ack(sock, block_number, server_tid)  # ACK 전송

                    # 수신된 데이터 크기가 블록 사이즈(512)보다 작으면 전송 완료
                    if len(file_block) < BLOCK_SIZE:
                        print(f"✅ 파일 다운로드 성공: {filename} ({os.path.getsize(filename)} bytes)")
                        break
                    expected_block_number += 1

                else:
                    # 중복되거나 순서가 어긋난 데이터 블록 수신 시:
                    # 마지막으로 성공적으로 수신한 블록에 대한 ACK를 재전송하여 서버에 알림
                    send_ack(sock, expected_block_number - 1, server_tid)

                # --- 다음 데이터 블록 수신 대기 (ACK 전송 후) ---
                try:
                    data, server_tid = sock.recvfrom(BLOCK_SIZE + 4)
                except socket.timeout:
                    # 타임아웃 발생 시 마지막 ACK 재전송 후 재시도
                    # (서버가 ACK를 못 받았다고 판단하고 데이터를 재전송하도록 유도)
                    send_ack(sock, expected_block_number - 1, server_tid)
                    continue
            else:
                print(f"🚫 예상치 못한 Opcode {opcode} 수신.")
                break


def tftp_put(sock, filename, server_address):
    """
    TFTP 'put' (업로드) 작업을 수행합니다.
    1. 서버에 WRQ 패킷 전송
    2. ACK 0 수신 대기
    3. 파일 데이터 전송 및 ACK 수신 반복
    """
    print(f"⬆️ 파일 업로드 요청: {filename}")

    # 로컬 파일 존재 여부 확인
    if not os.path.exists(filename):
        print(f"🚫 업로드 실패: 로컬 파일 {filename}을(를) 찾을 수 없습니다.")
        sys.exit()

    # WRQ 패킷 생성
    request_packet = create_request_packet('WRQ', filename, DEFAULT_TRANSFER_MODE)
    server_tid = server_address  # 초기 요청은 69번 포트 (또는 지정된 포트)로 전송

    # --- WRQ 전송 및 ACK 0 대기 루프 (재시도 로직 포함) ---
    retries = 0
    while retries < MAX_TRY:
        try:
            sock.sendto(request_packet, server_tid)
            # WRQ에 대한 응답은 ACK 0 (4바이트) 또는 ERROR 패킷입니다.
            data, server_tid = sock.recvfrom(4)

            opcode = int.from_bytes(data[:2], 'big')
            block_number = int.from_bytes(data[2:4], 'big')

            if opcode == OPCODE['ERROR']:
                handle_error(data)
                sys.exit()

            if opcode == OPCODE['ACK'] and block_number == 0:
                print("   ACK 0 수신. 파일 전송 시작.")
                break

            print(f"   [Warning] 예상치 못한 응답 Opcode={opcode}, Block={block_number}")

        except socket.timeout:
            retries += 1
            if retries == MAX_TRY:
                print("🚫 서버 응답이 없습니다. TFTP 업로드 실패.")
                sys.exit()

    # --- 데이터 전송 루프 (ACK 0 수신 후) ---
    block_number = 1
    with open(filename, 'rb') as file:
        while True:
            # 파일에서 512바이트씩 읽어옵니다.
            data_chunk = file.read(BLOCK_SIZE)

            # DATA 패킷 생성
            data_packet = pack(f'>hh{len(data_chunk)}s', OPCODE['DATA'], block_number, data_chunk)

            # --- DATA 전송 및 ACK 대기 루프 (재시도 로직 포함) ---
            retries = 0
            while retries < MAX_TRY:
                try:
                    sock.sendto(data_packet, server_tid)
                    ack_data, server_tid = sock.recvfrom(4)

                    ack_opcode = int.from_bytes(ack_data[:2], 'big')
                    ack_block = int.from_bytes(ack_data[2:4], 'big')

                    if ack_opcode == OPCODE['ERROR']:
                        handle_error(ack_data)
                        sys.exit()

                    # 올바른 ACK(현재 보낸 블록 번호와 일치)를 받으면 다음 블록으로 진행
                    if ack_opcode == OPCODE['ACK'] and ack_block == block_number:
                        break  # 내부 재시도 루프 탈출

                    # 중복 ACK 또는 잘못된 ACK은 무시하고 루프 재실행 (타임아웃 대기)

                except socket.timeout:
                    retries += 1

            if retries == MAX_TRY:
                print("🚫 서버로부터 ACK를 받지 못했습니다. 업로드 실패.")
                break

            # 마지막 데이터 블록(512바이트 미만)이었다면 전송 완료
            if len(data_chunk) < BLOCK_SIZE:
                print(f"✅ 파일 업로드 성공: {filename} ({os.path.getsize(filename)} bytes)")
                break

            block_number += 1


def main():
    # --- 명령행 인자 파싱 ---
    parser = argparse.ArgumentParser(description='TFTP client program')
    parser.add_argument(dest="host", help="Server IP address or hostname", type=str)
    parser.add_argument(dest="operation", help="get or put a file", type=str)
    parser.add_argument(dest="filename", help="name of file to transfer", type=str)
    parser.add_argument("-p", "--port", dest="port", type=int)
    args = parser.parse_args()

    # --- 호스트 이름 해석 ---
    try:
        server_ip = socket.gethostbyname(args.host)  # 도메인 이름을 IP로 변환
    except socket.gaierror:
        print(f"❌ 호스트 오류: '{args.host}'에 해당하는 IP 주소를 찾을 수 없습니다.")
        sys.exit()

    # 포트 설정 (인자가 없으면 기본값 69)
    server_port = args.port if args.port is not None else DEFAULT_PORT
    server_address = (server_ip, server_port)

    # --- UDP 소켓 생성 ---
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(TIME_OUT)

    print(f"⚙️ TFTP 클라이언트 시작")
    print(f"   서버: {args.host} ({server_ip}), 포트: {server_port}")
    print(f"   작업: {args.operation}, 파일: {args.filename}")
    print("-" * 30)

    # --- 작업 수행 ---
    if args.operation.lower() == 'get':
        tftp_get(sock, args.filename, server_address)
    elif args.operation.lower() == 'put':
        tftp_put(sock, args.filename, server_address)
    else:
        print("❌ 유효하지 않은 operation: 'get' 또는 'put'이어야 합니다.")

    sock.close()


if __name__ == "__main__":
    main()
