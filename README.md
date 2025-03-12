# Advanced Port Scanner

Advanced Port Scanner es una herramienta de escaneo de puertos desarrollada en Python, que utiliza múltiples métodos de escaneo, incluyendo Nmap, Socket y Scapy.

## Características
- **Stealth Scan (-sS)** con Nmap
- **Detailed Scan (-sV)** con Nmap
- **Basic Scan** con sockets en Python
- **Advanced Scan** con Scapy
- Recomendaciones para mejorar el anonimato al realizar escaneos

## Instalación
Asegúrate de tener Python instalado en tu sistema. Luego, instala las dependencias necesarias:

```bash
pip install python-nmap scapy
```

## Uso
Ejecuta el script como root con Python:

```bash
sudo python3 scanner.py
```

Sigue las instrucciones en pantalla para elegir el tipo de escaneo que deseas realizar.

## Anonimato
Se recomienda utilizar **Tor** y **ProxyChains** para mejorar el anonimato:

```bash
sudo apt install tor proxychains
sudo systemctl start tor
sudo proxychains python3 scanner.py
```

## Contribuciones
Las contribuciones son bienvenidas. Si deseas mejorar la herramienta, abre un issue o envía un pull request.

## Licencia
Este proyecto está bajo la Licencia MIT. Puedes modificarlo y distribuirlo libremente.

