import asyncio
import random
import time

# Configura o endereço e a porta para o servidor UDP
UDP_IP = "192.168.1.227"
UDP_PORT = 1234

# Parâmetros de Diffie-Hellman
g = 5
p = 23
device_keys = {}  # Dicionário para armazenar as chaves compartilhadas de cada dispositivo
device_last_seen = {}  # Armazena o último tempo que cada dispositivo foi visto
TIMEOUT = 10  # Tempo em segundos para considerar que um dispositivo caiu

def mod_exp(base, exp, mod):
    result = 1
    while exp > 0:
        if exp % 2 == 1:
            result = (result * base) % mod
        base = (base * base) % mod
        exp //= 2
    return result

def generate_keys():
    private_key = random.randint(1, p-1)
    public_key = mod_exp(g, private_key, p)
    return private_key, public_key

# Função para descriptografar a mensagem com XOR usando a chave compartilhada
def decrypt_message(message, key):
    decrypted_message = ''.join(chr(ord(char) ^ (key & 0xFF)) for char in message)
    return decrypted_message

# Função para atualizar a última vez que um dispositivo foi visto
def update_last_seen(addr):
    device_last_seen[addr] = time.time()

# Função para verificar se algum dispositivo perdeu a conexão
def check_timeouts():
    current_time = time.time()
    for addr, last_seen in list(device_last_seen.items()):
        if current_time - last_seen > TIMEOUT:
            print(f"Dispositivo {addr} desconectado (timeout)")
            # Remover as chaves associadas ao dispositivo desconectado
            del device_keys[addr]
            del device_last_seen[addr]

class UDPServerProtocol(asyncio.DatagramProtocol):
    def connection_made(self, transport):
        self.transport = transport
        print(f"Servidor UDP iniciado em {UDP_IP}:{UDP_PORT}")

    def datagram_received(self, data, addr):
        global device_keys

        print(f"Recebido {len(data)} bytes de {addr}")

        # Atualizar o tempo de última comunicação
        update_last_seen(addr)

        if addr not in device_keys:
            try:
                # Iniciar a troca de chaves com o novo dispositivo
                data_str = data.decode().strip()
                client_public_key = int(data_str)
                private_key, public_key = generate_keys()
                shared_key = mod_exp(client_public_key, private_key, p)
                device_keys[addr] = shared_key
                print(f"Chave pública recebida do dispositivo {addr}: {client_public_key}")
                print(f"Chave compartilhada calculada para {addr}")

                # Enviar a chave pública do servidor para o dispositivo
                self.transport.sendto(str(public_key).encode(), addr)
                print(f"Chave pública do servidor enviada para {addr}")
            except ValueError:
                print(f"Erro ao converter a chave pública recebida: {data.decode()} de {addr}")
                # Enviar mensagem de reconexão para o cliente
                reconnect_message = "RTC"
                self.transport.sendto(reconnect_message.encode(), addr)
                print(f"Mensagem de reconexão enviada para {addr}")
        else:
            try:
                # Descriptografar a mensagem recebida com a chave compartilhada
                shared_key = device_keys[addr]
                encrypted_message = data.decode()
                decrypted_message = decrypt_message(encrypted_message, shared_key)
                print(f"Mensagem descriptografada recebida de {addr}: {decrypted_message}")

                # Enviar uma resposta de status (opcional)
                response_message = f"Recebido: {decrypted_message}"
                self.transport.sendto("Hello Client".encode(), addr)
            except Exception as e:
                print(f"Erro ao processar a mensagem de {addr}: {e}")
                reconnect_message = "RTC"
                self.transport.sendto(reconnect_message.encode(), addr)
                print(f"Mensagem de reconexão enviada para {addr}")

async def main():
    print("Iniciando servidor UDP...")
    loop = asyncio.get_running_loop()

    # Cria o servidor UDP
    transport, protocol = await loop.create_datagram_endpoint(
        lambda: UDPServerProtocol(),
        local_addr=(UDP_IP, UDP_PORT)
    )

    try:
        while True:
            await asyncio.sleep(1)
            # Verificar se algum dispositivo caiu (timeout)
            check_timeouts()
    finally:
        transport.close()

asyncio.run(main())
