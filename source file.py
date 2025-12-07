#!/usr/bin/python3
'''
$ my_tftp host <get|put> filename [-p port_mumber]
'''
import socket
import argparse
from struct import pack
import sys
import os

DEFAULT_PORT = 69
BLOCK_SIZE = 512
DEFAULT_TRANSFER_MODE = 'octet'
TIME_OUT = 1.0  # 타임아웃 1초 설정
MAX_TRY = 5  # 최대 재시도 횟수
DEFAULT_ENCODING = 'utf-8'  # NameError 해결: 인코딩 정의

OPCODE = {'RRQ': 1, 'WRQ': 2, 'DATA': 3, 'ACK': 4, 'ERROR': 5}
MODE = {'netascii': 1, 'octet': 2, 'mail': 3}

ERROR_CODE = {
    0: "Not defined, see error message (if any).",
    1: "File not found (TFTP Server).",
    2: "Access violation.",
    3: "Disk full or allocation exceeded.",
    4: "Illegal TFTP operation.",
    5: "Unknown transfer ID.",
    6: "File already exists (TFTP Server).",
    7: "No such user."
}


# --- 패킷 생성 함수 ---

def create_rrq_wrq(opcode_type, filename, mode):
    """RRQ 또는 WRQ 패킷을 생성"""
    format = f'>h{len(filename)}sB{len(mode)}sB'
    return pack(format, OPCODE[opcode_type], bytes(filename, 'utf-8'), 0, bytes(mode, 'utf-8'), 0)


def create_data(seq_num, data_block):
    """DATA 패킷을 생성"""
    format = f'>hh{len(data_block)}s'
    return pack(format, OPCODE['DATA'], seq_num, data_block)


def create_ack(seq_num):
    """ACK 패킷을 생성"""
    format = f'>hh'
    return pack(format, OPCODE['ACK'], seq_num)


def create_error(code, message):
    """ERROR 패킷을 생성"""
    # 에러 메시지는 NULL 종단되어야 합니다.
    format = f'>hh{len(message)}sB'
    return pack(format, OPCODE['ERROR'], code, bytes(message, DEFAULT_ENCODING), 0)


# --- 메인 실행 로직 ---

def transfer_file(operation, filename, host, port):
    """파일 전송(get/put)을 수행하는 메인 함수"""

    # 1. 호스트 이름 해석 (도메인 네임 지원)
    try:
        server_ip = socket.gethostbyname(host)
        print(f"Resolved host '{host}' to IP: {server_ip}")
    except socket.gaierror:
        print(f"Error: Could not resolve hostname '{host}'")
        sys.exit(1)

    server_address = (server_ip, port)

    # 2. 소켓 설정
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(TIME_OUT)

    # TFTP 상태 변수 초기화
    expected_block_number = 1
    acked_block_number = 0
    retry_count = 0
    server_tid = None
    initial_packet = None
    last_packet_sent = None

    # 3. OPERATION 초기화 (RRQ/WRQ)
    if operation.lower() == 'get':
        print(f"Preparing to GET file '{filename}'...")
        # GET 시에는 로컬 파일이 없어야 하므로, 이미 있다면 경고
        if os.path.exists(filename):
            print(f"Warning: Local file '{filename}' exists and will be overwritten.")
        initial_packet = create_rrq_wrq('RRQ', filename, DEFAULT_TRANSFER_MODE)
        file_mode = 'wb'

    elif operation.lower() == 'put':
        print(f"Preparing to PUT file '{filename}'...")
        # 로컬 파일 존재 여부 확인 및 권한 검사
        if not os.path.exists(filename):
            print(f"Error: Local file '{filename}' not found.")
            sys.exit(1)
        if not os.access(filename, os.R_OK):
            print(f"Error: Local file '{filename}' access denied.")
            sys.exit(1)

        initial_packet = create_rrq_wrq('WRQ', filename, DEFAULT_TRANSFER_MODE)
        file_mode = 'rb'

    else:
        print(f"Error: Operation '{operation}' not supported. Use 'get' or 'put'.")
        sys.exit(1)

    # 4. 파일 열기
    try:
        file = open(filename, file_mode)
    except IOError as e:
        print(f"Error opening local file: {e}")
        sys.exit(1)

    # 5. 첫 번째 패킷 전송 (RRQ 또는 WRQ)
    sock.sendto(initial_packet, server_address)
    print(f"Initial {operation.upper()} message sent to {server_address}. Waiting for response...")
    last_packet_sent = initial_packet

    # 6. 메인 전송 루프
    while True:
        try:
            data, current_server_address = sock.recvfrom(BLOCK_SIZE + 4)

            # 6-1. TID 검증 및 설정
            if server_tid is None:
                server_tid = current_server_address  # 첫 응답 서버 주소를 TID로 설정
                print(f"TID established with {server_tid}")
            elif current_server_address != server_tid:
                # Unknown transfer ID (TID) 오류 처리 (ERROR 5)
                error_msg = create_error(5, "Unknown transfer ID")
                sock.sendto(error_msg, current_server_address)
                print(f'Warning: Packet from unknown TID {current_server_address}. Sent ERROR 5.')
                continue

            retry_count = 0  # 패킷 수신 성공 시 재시도 횟수 초기화
            opcode = int.from_bytes(data[:2], 'big')

        except socket.timeout:
            # 6-2. 타임아웃 발생 시 재시도
            retry_count += 1
            print(f'Timeout ({retry_count}/{MAX_TRY}). Retrying...')

            if retry_count > MAX_TRY:
                print("Max retries reached. Transfer failed.")
                file.close()
                sys.exit(1)

            # 마지막으로 보낸 패킷 재전송
            # 서버 TID가 설정되지 않았다면 (첫 RRQ/WRQ 응답을 기다리는 중) 서버 주소로 전송
            sock.sendto(last_packet_sent, server_tid or server_address)
            print(f"=> Retransmitting last packet.")
            continue

        # 6-3. 오류 패킷 수신 처리
        if opcode == OPCODE['ERROR']:
            error_code = int.from_bytes(data[2:4], byteorder='big')
            # 오류 메시지 디코딩 (DEFAULT_ENCODING 사용)
            error_msg = data[4:].split(b'\x00')[0].decode(DEFAULT_ENCODING, errors='ignore')
            print(
                f'\n*** Error received (Code {error_code}): {ERROR_CODE.get(error_code, "Unknown Error")} - {error_msg} ***')
            file.close()
            break

        # 6-4. GET (다운로드) 처리
        if operation.lower() == 'get':
            if opcode == OPCODE['DATA']:
                block_number = int.from_bytes(data[2:4], 'big')
                file_block = data[4:]

                if block_number == expected_block_number:
                    # 순차적 수신 성공
                    file.write(file_block)
                    print(f'<= Received block {block_number}. Writing {len(file_block)} bytes.')

                    # ACK 보내기
                    last_packet_sent = create_ack(block_number)
                    sock.sendto(last_packet_sent, server_tid)

                    acked_block_number = block_number
                    expected_block_number += 1

                    # 마지막 블록 확인 (512바이트 미만)
                    if len(file_block) < BLOCK_SIZE:
                        print(f"\n--- GET complete. Total blocks: {acked_block_number} ---")
                        file.close()
                        break

                elif block_number == acked_block_number:
                    # 중복 패킷 수신: 마지막 ACK 재전송
                    sock.sendto(last_packet_sent, server_tid)
                    print(f'Duplicate block {block_number} received. Resending ACK.')

                else:
                    # 예상치 못한 블록 번호 수신: 마지막 성공 블록의 ACK 재전송
                    if last_packet_sent and (int.from_bytes(last_packet_sent[:2], 'big') == OPCODE['ACK']):
                        sock.sendto(last_packet_sent, server_tid)
                        print(f'Out-of-order block {block_number} received. Resending ACK for {acked_block_number}.')


        # 6-5. PUT (업로드) 처리
        elif operation.lower() == 'put':
            if opcode == OPCODE['ACK']:
                block_number = int.from_bytes(data[2:4], 'big')

                if block_number == expected_block_number - 1:
                    # ACK 수신 성공 (ACK는 이전에 보낸 DATA 번호 또는 WRQ에 대한 ACK 0)
                    print(f'=> Received ACK for block {block_number}.')

                    # WRQ에 대한 ACK 0 수신 시: 첫 번째 DATA 블록 전송
                    if block_number == 0:
                        expected_block_number = 1

                    # 파일에서 데이터 블록 읽기
                    file_block = file.read(BLOCK_SIZE)

                    if not file_block:
                        # 파일 전송 완료 (마지막 블록을 이미 보냈고 ACK를 받았으므로)
                        print("\n--- PUT complete. All data sent and acknowledged. ---")
                        file.close()
                        break

                    # DATA 패킷 생성 및 전송
                    data_packet = create_data(expected_block_number, file_block)
                    sock.sendto(data_packet, server_tid)

                    last_packet_sent = data_packet
                    print(f'=> Sent DATA block {expected_block_number}. Size: {len(file_block)}')
                    expected_block_number += 1

                else:
                    # 예상치 못한 블록 번호의 ACK 수신 (중복 또는 순서 오류):
                    # 이전 DATA 패킷 재전송 (타임아웃 로직에서 처리되도록 유도)
                    print(f'Out-of-order ACK {block_number} received. Ignoring.')

        else:
            # 알 수 없는 Opcode 수신 (Illegal TFTP operation)
            error_msg = create_error(4, "Illegal TFTP operation")
            sock.sendto(error_msg, current_server_address)
            print(f'Illegal TFTP operation (Opcode {opcode}) received. Sent ERROR 4.')
            file.close()
            break


# --- 파서 및 메인 실행부 ---

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='TFTP client program')
    # 호스트 이름/IP 주소
    parser.add_argument(dest="host", help="Server hostname or IP address", type=str)
    # get 또는 put
    parser.add_argument(dest="operation", help="get or put a file", type=str)
    # 전송할 파일 이름
    parser.add_argument(dest="filename", help="name of file to transfer", type=str)
    # 포트 설정 (-p)
    parser.add_argument("-p", "--port", dest="port", type=int, default=DEFAULT_PORT,
                        help=f"Server port number (default: {DEFAULT_PORT})")
    args = parser.parse_args()

    transfer_file(args.operation, args.filename, args.host, args.port)
