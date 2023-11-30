# Escaner de puertos basico
Este script en python realiza un escaneo a los puertos de una direccion
ip especificada por el usuario, se pueden realizar 3 tipos de escaneo que son:
-rg = rango de puertos
-ps = puertos especificos
-p = un solo puerto
Tambien puede ser utilizado para averiguar la version del servidor

## Uso
Para escanear puertos con scanlow ejecute el siguiente comando, remplazando 
'expample.com' por el objetivo, el modo de uso es:
python3 scanlow -t example.com -p 80
python3 scanlow -t example.com -vs

### 1. Instalacion de dependencias:
Antes de ejecutar el script, asegúrate de instalar las 
dependencias necesarias utilizando el siguiente comando:

```bash
pip install tqdm==4.66.1
pip install scapy==2.5.0
