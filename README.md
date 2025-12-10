# TFTP-2189041 성효진

📂 TFTP Client Implementation (Python)
본 프로젝트는 Python 소켓 API를 사용하여 TFTP (Trivial File Transfer Protocol) 클라이언트를 구현한 결과물입니다. RFC 1350 표준을 준수하며, UDP 기반의 비연결성 통신에서 신뢰성을 보장하기 위한 Stop-and-Wait 방식과 재전송(Retransmission) 로직을 포함하고 있습니다.

# 1. 프로그램 개요
파일명: my_tftp.py

개발 언어: Python 3

통신 프로토콜: UDP (User Datagram Protocol)

주요 기능:

원격 서버로부터 파일 다운로드 (GET)

원격 서버로 파일 업로드 (PUT)

도메인 네임(Domain Name) 해석 지원

패킷 손실 시 타임아웃 및 재전송 처리

서버 에러 코드 파싱 및 처리

# 2. 실행 방법 (Usage)
터미널에서 다음과 같은 형식으로 실행합니다.

기본 포트(69) 사용 시
$ python3 my_tftp.py <Host> <Operation> <Filename>

특정 포트 지정 시 (-p 옵션)
$ python3 my_tftp.py <Host> <Operation> <Filename> -p <Port>

**실행 예시:**
다운로드 (GET)
$ python3 my_tftp.py 203.250.133.88 get tftp.conf

업로드 (PUT)
$ python3 my_tftp.py genie.pcu.ac.kr put assignment.txt -p 69

# 3. 코드 구조 및 핵심 로직 분석

    이 코드는 크게 설정 및 상수 정의, 패킷 생성 함수, 메인 전송 로직으로 구성되어 있습니다.


    설정 및 상수 (Lines 11-29)
    기본 설정: DEFAULT_PORT = 69, BLOCK_SIZE = 512 등 TFTP 표준 상수를 정의했습니다.


    타임아웃 설정 (Line 14): TIME_OUT = 1.0초로 설정하여, 패킷 유실 시 1초 대기 후 재전송을 준비합니다.


    Opcode & Error Code: RRQ, WRQ, DATA, ACK, ERROR 패킷의 Opcode와 에러 메시지를 딕셔너리로 관리하여 가독성을 높였습니다.


    패킷 생성 (Struct Packing) (Lines 33-57)
    C언어 구조체와 호환되는 바이너리 데이터를 생성하기 위해 struct.pack을 사용했습니다.


    create_rrq_wrq: 파일 이름과 전송 모드를 포함한 요청 패킷 생성.


    create_data / create_ack: 데이터 블록과 수신 확인(ACK) 패킷 생성.


    create_error: 오류 코드와 메시지를 포함한 에러 패킷 생성.


    메인 로직: transfer_file 함수 (Line 62~)


1) 초기화 및 소켓 설정 (Lines 65-80)

    DNS 조회 (Line 66): socket.gethostbyname(host)를 사용하여 도메인 이름을 IP 주소로 변환합니다.


    소켓 생성 (Line 76): socket.SOCK_DGRAM을 사용하여 UDP 소켓을 생성하고, sock.settimeout(TIME_OUT)으로 타임아웃을 설정합니다.   



2) Operation 별 사전 준비 (Lines 87-111)

    GET 요청 시: 로컬에 동일한 파일이 존재하는지 확인하여 덮어쓰기 경고를 출력하고, 파일을 쓰기 모드(wb)로 엽니다.

  
    PUT 요청 시: 로컬 파일이 실제로 존재하는지, 읽기 권한이 있는지 사전에 검사(os.access)하고, 읽기 모드(rb)로 엽니다. 



3) TID (Transfer ID) 핸들링 (Lines 131-139)

    TFTP는 초기 연결(69번 포트) 이후, 데이터 전송 단계에서는 서버가 임의로 할당한 새로운 포트(TID)를 사용합니다.

  
    Line 132: 서버로부터 첫 응답이 온 주소(current_server_address)를 server_tid 변수에 저장합니다.


    Line 135: 이후 수신되는 패킷이 저장된 server_tid와 다를 경우, 잘못된 소스에서 온 패킷으로 간주하여 ERROR 5를 전송하고 무시합니다. 



4) 신뢰성 보장: 타임아웃 및 재전송 (Lines 147-163)

    UDP의 신뢰성 문제를 해결하기 위한 핵심 로직입니다.


    Line 147: socket.timeout 예외가 발생하면 retry_count를 증가시킵니다.


    Line 158: MAX_TRY(5회)까지 응답이 없으면 last_packet_sent에 저장해 둔 마지막 패킷(RRQ/WRQ 또는 마지막 ACK/DATA)을 재전송합니다. 



5) 데이터 송수신 처리 (Lines 172-239)

    GET 처리 (Lines 173-205):

  
    DATA 패킷을 수신하면 블록 번호를 검증하고 파일에 씁니다.


    정상 수신 시 create_ack로 ACK를 전송합니다.


    수신된 데이터 크기가 512바이트 미만이면 전송을 종료합니다.


    PUT 처리 (Lines 208-239):


    ACK 패킷을 수신하면 블록 번호를 확인합니다.

  
    file.read(BLOCK_SIZE)로 파일을 읽어 create_data로 DATA 패킷을 전송합니다. 



6) 에러 처리 (Lines 166-170)

    서버로부터 ERROR Opcode를 수신하면, 에러 코드와 메시지를 파싱 하여 출력하고 즉시 작업을 중단합니다.


# 4. 핵심 요약
  
    이 코드는 "UDP 위에서 동작하지만, Stop-and-Wait ARQ 방식을 통해 데이터의 무결성과 순서를 보장하는 파일 전송 클라이언트" 입니다. 단순히 패킷을 보내는 것에 그치지 않고, 네트워크 지연이나 손실 상황을 대비한 재전송 로직과 예외 처리가 구현되있습니다.
