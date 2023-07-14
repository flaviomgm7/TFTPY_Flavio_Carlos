import os
import sys
import argparse
import ipaddress
import re
import struct
import string
from socket import (
    socket,
    herror,
    gaierror,
    gethostbyaddr,
    gethostbyname_ex,
    AF_INET, SOCK_DGRAM,
)

MAX_DATA_LEN = 512            # bytes
MAX_BLOCK_NUM = 2**16 - 1  # 0..65535
INACTIVITY_TIMEOUT = 25.0     # segs
DEFAULT_MODE = 'octet'
DEFAULT_BUFFER_SIZE = 8192    # bytes
DEFAULT_PORT = 69

RRQ = 1   
WRQ = 2   
DAT = 3   
ACK = 4   
ERR = 5
LIST= 6   
          

ERR_NOT_DEFINED = 0
ERR_FILE_NOT_FOUND = 1
ERR_ACCESS_VIOLATION = 2


ERROR_MESSAGES = {
    ERR_NOT_DEFINED: 'Not defined, see error message (if any)',
    ERR_FILE_NOT_FOUND: 'File not found',
    ERR_ACCESS_VIOLATION: 'Access violation',
    
}

INET4Address = tuple[str, int]        



def get_file(server_addr: INET4Address, file_name: str, dest_file: str):
    with socket(AF_INET, SOCK_DGRAM) as sock:
        sock.settimeout(INACTIVITY_TIMEOUT)
        rrq = pack_rrq(file_name)
        sock.sendto(rrq, server_addr)
        next_block_num = 1
        with open(dest_file, 'wb') as file:
            while True:
                try:
                    packet, server_addr = sock.recvfrom(DEFAULT_BUFFER_SIZE)
                except socket.timeout:
                    raise NetworkError('Conexão Expirada')

                opcode = unpack_opcode(packet)

                if opcode == DAT:
                    block_num, data = unpack_dat(packet)
                    if block_num not in (next_block_num, next_block_num - 1):
                        raise ProtocolError(f'Block Number Inesperado: {block_num}')
                    
                    if block_num == next_block_num:
                        file.write(data)
                        next_block_num += 1

                    ack = pack_ack(block_num)
                    sock.sendto(ack, server_addr)

                    if len(data) < MAX_DATA_LEN:
                        break
                elif opcode == ERR:
                    error_code, error_msg = unpack_err(packet)
                    raise Err(error_code, error_msg)
                else:
                    raise ProtocolError(f'Opcode Inválido {opcode}')
                
        return

def put_file(server_addr: INET4Address, file_name: str, dest_file: str):
    with socket(AF_INET, SOCK_DGRAM) as sock:
        sock.settimeout(INACTIVITY_TIMEOUT)
        wrq = pack_wrq(file_name)
        sock.sendto(wrq, server_addr)
        next_block_num = 1
        with open(file_name, 'rb') as file:
            while True:
                data = file.read(MAX_DATA_LEN)
                if not data:
                    break

                dat = pack_dat(next_block_num, data)
                sock.sendto(dat, server_addr)

                while True:
                    try:
                        packet, server_addr = sock.recvfrom(DEFAULT_BUFFER_SIZE)
                    except socket.timeout:
                        raise NetworkError('Conexão Expirada')

                    opcode = unpack_opcode(packet)
                    if opcode == ACK:
                        block_num = unpack_ack(packet)
                        if block_num == next_block_num - 1:
                            next_block_num += 1
                            break
                        elif block_num != next_block_num:
                            raise ProtocolError(f'Block Number Inesperado: {block_num}')
                    elif opcode == ERR:
                        error_code, error_msg = unpack_err(packet)
                        raise Err(error_code, error_msg)
                    else:
                        raise ProtocolError(f'Opcode Inválido {opcode}')

def list_client_directories(directory=None):
    if directory is None:
        directory = os.getcwd()
    try:
        files = os.listdir(directory)
        for file in files:
            print(file)
    except FileNotFoundError:
        print("Diretório não encontrado.")

def list_server_directories(server_addr, INET4Address, directory=str):
    with socket(AF_INET, SOCK_DGRAM) as sock:
        sock.settimeout(INACTIVITY_TIMEOUT)
        list_rq = pack_list(directory)
        sock.sendto(list_rq, server_addr)
        
        while True:
            try:
                packet, server_addr = sock.recvfrom(DEFAULT_BUFFER_SIZE)
            except socket.timeout:
                raise NetworkError('Conexão Expirada')

            opcode = unpack_opcode(packet)

            if opcode == DAT:
                block_num, data = unpack_dat(packet)
                print(data.decode())
                
                ack = pack_ack(block_num)
                sock.sendto(ack, server_addr)

                if len(data) < MAX_DATA_LEN:
                    break
            elif opcode == ERR:
                error_code, error_msg = unpack_err(packet)
                raise Err(error_code, error_msg)
            else:
                raise ProtocolError(f'Opcode Inválido {opcode}')
            
def pack_list(directory: str) -> bytes:
    encoded_directory = directory.encode('utf-8') + b'\x00'
    fmt = f'!H{len(encoded_directory)}s'
    return struct.pack(fmt, LIST, encoded_directory)

def unpack_list(packet: bytes) -> str:
    directory = packet[2:-1].decode()
    return directory

def print_help():
    print("Comandos disponíveis:")
    print("dirC [diretório] - Listar arquivos no cliente")
    print("dirS [diretório] - Listar arquivos no servidor")
    print("get [arquivo_remoto] [arquivo_local] - Baixar arquivo do servidor")
    print("put [arquivo_local] [arquivo_remoto] - Enviar arquivo para o servidor")
    print("help - Exibir esta mensagem de ajuda")
    print("quit - Encerrar o programa")

def quit_program():
    sys.exit(0)

def print_menu():
    print("TFTP Client - Modo Interativo")
    print("Comandos disponíveis:")
    print("1. Listar arquivos no cliente: dirC [diretório]")
    print("2. Listar arquivos no servidor: dirS [diretório]")
    print("3. Baixar arquivo do servidor: get [arquivo_remoto] [arquivo_local]")
    print("4. Enviar arquivo para o servidor: put [arquivo_local] [arquivo_remoto]")
    print("5. Ajuda: help")
    print("6. Sair: quit")

def run_interactive_mode(server_addr):
    print_menu()
    
    while True:
        command = input("Digite um comando: ")

        if command.startswith("dirC"):
            parts = command.split()

            if len(parts) == 2:
                directory = parts[1]
                list_client_directories(directory)
            else:
                list_client_directories()

        elif command.startswith("dirS"):
            parts = command.split()
        
            if len(parts) == 2:
                directory = parts[1]
                list_server_directories(server_addr, directory)
            else:
                list_server_directories(server_addr, INET4Address)

        elif command.startswith("get"):
            parts = command.split()

            if len(parts) == 3:
                remote_file = parts[1]
                local_file = parts[2]
                get_file(server_addr, remote_file, local_file)
            else:
                print("Comando inválido.")

        elif command.startswith("put"):
            parts = command.split()

            if len(parts) == 3:
                local_file = parts[1]
                remote_file = parts[2]
                put_file(server_addr, local_file, remote_file)
            else:
                print("Comando inválido.")

        elif command == "help":
            print_help()

        elif command == "quit":
            quit_program()

        else:
            print("Comando inválido. Digite 'help' para obter a lista de comandos disponíveis")
def pack_rrq(file_name: str) -> bytes:
    return struct.pack('!H', RRQ) + file_name.encode() + b'\x00' + DEFAULT_MODE.encode() + b'\x00'

def pack_wrq(file_name: str) -> bytes:
    return struct.pack('!H', WRQ) + file_name.encode() + b'\x00' + DEFAULT_MODE.encode() + b'\x00'

def pack_dat(block_num: int, data: bytes) -> bytes:
    return struct.pack('!HH', DAT, block_num) + data

def pack_ack(block_num: int) -> bytes:
    return struct.pack('!HH', ACK, block_num)

def unpack_opcode(packet: bytes) -> int:
    return struct.unpack('!H', packet[:2])[0]

def unpack_ack(packet: bytes) -> int:
    return struct.unpack('!H', packet[2:4])[0]

def unpack_dat(packet: bytes) -> tuple[int, bytes]:
    return struct.unpack('!HH', packet[:4])[1], packet[4:]

def unpack_err(packet: bytes) -> tuple[int, str]:
    error_code = struct.unpack('!H', packet[:2])[0]
    error_msg = packet[2:-1].decode()
    return error_code, error_msg

class Err(Exception):
    def __init__(self, error_code: int, error_msg: str):
        super().__init__(f'Error {error_code}: {error_msg}')
        self.error_code = error_code
        self.error_msg = error_msg

class ProtocolError(Exception):
    pass

class NetworkError(Exception):
    pass

def validate_ipv4_address(ip: str) -> bool:
    try:
        ipaddress.IPv4Address(ip)
        return True
    except ipaddress.AddressValueError:
        return False

def resolve_server_address(server: str) -> INET4Address:
    if validate_ipv4_address(server):
        return server, DEFAULT_PORT

    try:
        ip_list = gethostbyname_ex(server)[2]
    except (herror, gaierror):
        raise NetworkError(f"Não foi possivel encontrar o hostname:  {server}")

    for ip in ip_list:
        if validate_ipv4_address(ip):
            return ip, DEFAULT_PORT

    raise NetworkError(f"Não foi possivel encontrar o hostname:  {server}")

def parse_arguments():
    parser = argparse.ArgumentParser(description='TFTP Client')
    parser.add_argument('operation', choices=['get', 'put'], help='Operation to perform: get or put')
    parser.add_argument('-p', '--port', type=int, default=DEFAULT_PORT, help='Server port')
    parser.add_argument('server', type=str, help='Server address or hostname')
    parser.add_argument('source_file', type=str, help='Source file to transfer')
    parser.add_argument('dest_file', type=str, help='Destination file')
    return parser.parse_args()

def main():
    if args.operation == 'get':
        dest_file = args.dest_file or args.source_file
        get_file(server_addr, args.source_file, dest_file)
        print(f'Download com sucesso {args.source_file} as {dest_file}')
    elif args.operation == 'put':
        put_file(server_addr, args.source_file)
        print(f'Upload com sucesso {args.source_file}')
    elif args.operation == 'dirS':
        list_server_directories(server_addr, args.directory)
    else:
        raise argparse.ArgumentError(None, 'Operação Inválida')

         
if __name__ == "__main__":
    parser = argparse.ArgumentParser(prog='python3 clienteteste.py')
    parser.add_argument('-p', '--port', type=int, default=DEFAULT_PORT, help='Server port')
    parser.add_argument('server', type=str, nargs='?', help='Server address or hostname')

    args = parser.parse_args()



    if len(sys.argv) != 2:
        print("Uso Interativo: python3 nome_do_programa.py <endereço_ip>")
        sys.exit(1)
    
    if len(sys.argv) == 2:
        server_addr = (sys.argv[1], DEFAULT_PORT)
        run_interactive_mode(server_addr)
    