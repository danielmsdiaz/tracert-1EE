import socket
import struct
import time
from ip2geotools.databases.noncommercial import DbIpCity

def get_location(location_ip):
    formatted_address = ''

    if location_ip.city is not None:
        formatted_address += f" {location_ip.city},"
    if location_ip.region is not None:
        formatted_address += f" {location_ip.region},"
    if location_ip.country is not None:
        formatted_address += f" {location_ip.country},"

    if formatted_address != '':
        return formatted_address
    else:
        return None

def tracert(destino, max_hops=30, timeout=3):
    port = 33434  # Porta do Traceroute (UDP)

    for ttl in range(1, max_hops + 1):
        try:
            ssnd = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
            ssnd.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)
            ssnd.settimeout(timeout)

            srcv = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            srcv.bind(('', port))
            srcv.settimeout(timeout)

            # Envia um pacote UDP para o destino
            ssnd.sendto(struct.pack('!HHHH', port, port, 8, 0) + b'0', (destino, port))

            # Tenta receber uma resposta ICMP
            start_time = time.time()
            buffer, addr = srcv.recvfrom(1024)
            end_time = time.time()

            # Calcula o tempo de ida e volta
            rtt = (end_time - start_time) * 1000

            # Obtém o IP do roteador
            router_ip = addr[0]

            # Obtém as coordenadas geográficas associadas ao IP
            location_ip = DbIpCity.get(router_ip, api_key='free')

            location = "-"

            if location_ip is not None and location_ip.country != 'ZZ':
                # Obtém a localização a partir das coordenadas
                location = get_location(location_ip)

            # Obtém o nome do host associado ao IP
            try:
                router_host = socket.gethostbyaddr(router_ip)[0]
                router = f"{router_host} [{router_ip}]"
            except socket.herror:
                router = router_ip

            print(f"(UDP) {ttl}. {router} {location} {rtt:.3f} ms")

            # Se atingiu o destino, sai do loop
            if router_ip == destino:
                break

        except socket.timeout:
            print("Erro UDP: timed out")
            # Em caso de timeout, tenta enviar um pacote TCP
            try:
                print("Enviando pacote TCP...")
                ssnd_tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                ssnd_tcp.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)
                ssnd_tcp.settimeout(timeout)

                # Conecta e envia um pacote TCP para a porta 80 (por exemplo)
                ssnd_tcp.connect((destino, 80))
                ssnd_tcp.send(b'0')

                start_time_tcp = time.time()
                buffer_tcp = ssnd_tcp.recv(1024)
                end_time_tcp = time.time()

                rtt_tcp = (end_time_tcp - start_time_tcp) * 1000

                # Obtém o IP do roteador
                router_ip_tcp = ssnd_tcp.getpeername()[0]

                # Obtém as coordenadas geográficas associadas ao IP
                location_ip_tcp = DbIpCity.get(router_ip_tcp, api_key='free')

                location_tcp = "-"

                if location_ip_tcp is not None and location_ip_tcp.country != 'ZZ':
                    # Obtém a localização a partir das coordenadas
                    location_tcp = get_location(location_ip_tcp)

                # Obtém o nome do host associado ao IP
                try:
                    router_host_tcp = socket.gethostbyaddr(router_ip_tcp)[0]
                    router_tcp = f"{router_host_tcp} [{router_ip_tcp}]"
                except socket.herror:
                    router_tcp = router_ip_tcp

                print(f"{ttl}. (TCP) {router_tcp} {location_tcp} {rtt_tcp:.3f} ms")

                if router_tcp == destino:
                    print("Destino encontrado!")
                    break

            except socket.error as e:
                print(f"Erro TCP: {e}")

            finally:
                ssnd_tcp.close()

        except socket.error as e:
            print(f"Erro: {e}")
            break

        finally:
            ssnd.close()
            srcv.close()

if __name__ == "__main__":
    destino = input("Digite o endereço IP de destino: ")
    tracert(destino)
