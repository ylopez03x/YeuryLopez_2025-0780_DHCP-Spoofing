# DHCP Spoofing Attack
**Autor:** Yeury Lopez de Leon  
**Matrícula:** 2025-0780  
**Materia:** Seguridad de Redes  
**Fecha:** 31/05/2026  

[Ver demostración en YouTube](https://youtu.be/s4AO-4GtlBM)
---

## Objetivo del Laboratorio
Demostrar el ataque DHCP Spoofing en un entorno controlado,
evidenciando cómo un atacante puede levantar un servidor DHCP 
falso que entrega configuración maliciosa a los clientes de la red.

---

## Objetivo del Script
Levantar un servidor DHCP falso en Kali que responda antes que 
R1 a las solicitudes DHCP, entregando un gateway y DNS falsos 
apuntando a Kali.

### Parámetros usados
| Parámetro | Valor | Descripción |
|---|---|---|
| INTERFAZ | eth0 | Interfaz de Kali |
| KALI_IP | 172.25.78.10 | IP del servidor falso |
| FAKE_GATEWAY | 172.25.78.10 | Gateway falso (Kali) |
| FAKE_DNS | 172.25.78.10 | DNS falso (Kali) |
| IP_POOL | 172.25.78.150-199 | Pool de IPs falsas |
| LEASE_TIME | 3600 | Tiempo de lease en segundos |

### Requisitos para utilizar la herramienta
- Kali Linux con Python 3
- Librería Scapy instalada
- Permisos root
- IP Forwarding habilitado
- Misma red que las víctimas

---

## Documentación del funcionamiento del Script

**1. Escucha de solicitudes DHCP**  
El script usa `sniff()` para capturar paquetes UDP en puertos 
67 y 68, filtrando solo tráfico DHCP.

**2. Respuesta a DHCP Discover**  
Al recibir un Discover, Kali responde con un DHCP Offer 
entregando una IP del pool falso con gateway y DNS maliciosos.

**3. Respuesta a DHCP Request**  
Al recibir un Request, Kali confirma la asignación con un 
DHCP ACK, completando el proceso de envenenamiento.

**4. Registro de víctimas**  
El script registra todas las MACs que recibieron configuración 
falsa en el diccionario `asignaciones`.

---

## Documentación de la Red

### Topología
> <img width="705" height="617" alt="image" src="https://github.com/user-attachments/assets/de36b205-8930-4fbb-845a-3f85e0ab0c29" />


### Direccionamiento IP
| Dispositivo | Interfaz | Dirección IP | Máscara | Rol |
|---|---|---|---|---|
| R1 | fa0/0 | 172.25.78.1 | /24 | Gateway + DHCP Server |
| SW1 | VLAN1 | 172.25.78.2 | /24 | Switch Core - Root Bridge |
| SW2 | VLAN1 | 172.25.78.3 | /24 | Switch Acceso |
| Kali | eth0 | 172.25.78.10 | /24 | Atacante |
| PC1 | eth0 | 172.25.78.20 | /24 | Víctima 1 (estática) |
| PC2 | eth0 | 172.25.78.21 | /24 | Víctima 2 (DHCP) |

### Conexiones
| Dispositivo A | Interfaz | Dispositivo B | Interfaz |
|---|---|---|---|
| R1 | fa0/0 | SW1 | e0/0 |
| SW1 | e0/1 | Kali | eth0 |
| SW1 | e0/2 | PC1 | eth0 |
| SW1 | e0/3 | SW2 | e0/0 |
| SW2 | e0/1 | PC2 | eth0 |

### Herramientas utilizadas
- EVE-NG Community Edition
- Cisco IOL L2 v15.1 (SW1, SW2)
- Cisco IOS 3725 v12.4 Dynamips (R1)
- Kali Linux 2024
- Python 3 + Scapy
- VPCS (PC1, PC2)

---

## Capturas de Pantalla

### Script esperando solicitudes DHCP
> <img width="797" height="659" alt="image" src="https://github.com/user-attachments/assets/8207c67b-8a50-4e20-b152-f076553c439e" />


### DHCP Discover recibido y Offer enviado
> <img width="809" height="323" alt="image" src="https://github.com/user-attachments/assets/5ec0af09-5393-4ec5-a7ec-eface0d04f17" />

### PC2 con gateway falso
> <img width="492" height="306" alt="image" src="https://github.com/user-attachments/assets/a77dc1fa-2f0b-4eab-8d14-e1091a4517c7" />


---

## Contramedidas

### DHCP Snooping en SW1
```cisco
ip dhcp snooping
ip dhcp snooping vlan 1
interface ethernet 0/0
 ip dhcp snooping trust
interface ethernet 0/1
 ip dhcp snooping limit rate 10
```

### Verificación
> <img width="975" height="468" alt="image" src="https://github.com/user-attachments/assets/b4d15f43-1c53-4b43-8215-e7481bc18394" />


### Resultado
DHCP Snooping solo permite respuestas DHCP desde puertos de 
confianza, bloqueando cualquier servidor DHCP falso conectado 
a puertos no confiables.
