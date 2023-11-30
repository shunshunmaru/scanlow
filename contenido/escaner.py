# este modulo contiene las clases que realizan el escanero de los puertos
# la primera clase se encarga de escanear una direccion ip y un puerto
# especificado por el usuario tambien puede obtener el banner del servidor
# si se le pasa el nombre de dominio hace la resolucion a direccion IPv4
# la segunda clase se encarga de escanear una ip y un rango de puertos
# especificados por el usuario, tambien hace la resolucion del nombre de
# dominio a direccion IPv4

import time
import socket
import argparse
import ipaddress
import http.client
from tqdm import tqdm
import scapy.all as scapy

#############################
#    escaner mono puerto    #
#############################
class ConexionSocket:
    """
    Esta clase se encarga de escanear un puerto de una direccion IPv4
    o dominio especificada por el usuario
    parametros: 
    ip -> direccion ip a escanear
    puerto -> puerto al que se le verificara su estado
    """
    def __init__(self, ip, puerto):
        self.__ip = ip
        self.__puerto = puerto
        self.__sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.__sock.settimeout(2)
    
    @property
    def ip(self):
        return self.__ip

    @ip.setter
    def ip(self, nueva_ip):
        if nueva_ip != "":
            self.__ip = nueva_ip
        else:
            raise ValueError("El campo no puede estar vacio")

    @property
    def puerto(self):
        return self.__puerto
    
    @puerto.setter
    def puerto(self, nuevo_puerto):
        if isinstance(nuevo_puerto, int):
            self.__puerto = nuevo_puerto
        else:
            raise ValueError("El puerto debe ser de tipo entero")

    ##############################################
    # decorador que resulve el nombre de dominio #
    ##############################################
    def resolver_ip(func):
        """
        Este decorador hace la resolucion de un nombre de dominio
        a direccion IPv4 para ser procesada de manera mas sencilla
        """
        def wrapper(self, *args, **kwargs):
            try:
                nombre = self.__ip
                direccion_ip = socket.gethostbyname(nombre)
                print("La direccion ip de " + nombre + " es: " + direccion_ip)
                fun = func(self, *args, **kwargs)
                return fun
            except socket.gaierror:
                print("No fue posible resolver la direccion de: " + nombre)
            except ConnectionError as e:
                print("NO fue posible establecer la conexion %s 😒" % (e))
        return wrapper
    
    #################################
    # metodo que realiza el escaneo #
    #################################
    @resolver_ip
    def escan(self):
        """
        Este metodo se encarga de escanear una direccion ip y un puerto especifico
        """
        with self.__sock as sock:
            try:
                resultado = sock.connect_ex((self.__ip, self.__puerto))
                sock.close()

                total_iteraciones = 100
                with tqdm(total = total_iteraciones, desc = "Escaneando puerto", ascii = True) as barra_de_carga:
                    for _ in range(total_iteraciones):
                        time.sleep(0.01)
                        barra_de_carga.update(1)

                if resultado == 0:
                    servicio = socket.getservbyport(self.__puerto)
                    print("El puerto %s se encuentra abierto con el servicio: %s 😈" % (self.__puerto, servicio))
                elif resultado == 11:
                    print("El puerto se encuentra filtrado 💀")
                else:
                    print("El puerto se encuetra cerrado")
            except ConnectionError as e:
                print("No fue posible establecer la conexion %s 😒" % (e))
            except KeyboardInterrupt:
                print("El programa fue detenido por el usuario")

    ####################################
    # obtiene el banner de un servidor #
    ####################################
    def banner(self):
        """
        Este metodo obtiene el banner de un servidor de una direccion ip o nombre
        de dominio especificado por el usuario
        """
        with self.__sock as sock:
            try:
                sock.settimeout(1)
                sock.connect((self.__ip, self.__puerto))
                sock.send(b"GET / HTTP/1.1\r\nHost:" + self.__ip.encode("utf-8") +  b"\r\n\r\n")
                banner = sock.recv(1024)
                print("\nBanner del servidor: 😈")
                print(banner.decode("utf-8"))
            except (socket.timeout, ConnectionRefusedError):
                print("No fue posible obtener el banner del servidor")
            except KeyboardInterrupt:
                print("El programa fue deteniso por el usuario")
    
######################################
#   escanea un rango de de puertos   #
######################################
class Rango:
    """
    Realiza un escaneo de los puertos en el rango especificado y devuelve los resultados.
    
    Args:
    - inicio (int): Puerto inicial, por ejemplo, puerto 21.
    - fin (int): Puerto final a escanear.
    - tiempo (float): Tiempo de espera entre cada solicitud. Como recomendación,
                        los tiempos superiores a 1 segundo generan resultados más confiables.
    """
    def __init__(self, ip):
        self.__ip = ip
        self.__sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    @property
    def ip(self):
        return self.__ip

    @ip.setter
    def ip(self, nueva_ip):
        if nueva_ip != "":
            self.__ip = nueva_ip
        else:
            raise ValueError("El campo no puede estar vacio")
        
    ##############################################
    # decorador que resulve el nombre de dominio #
    ##############################################
    def resolver_ip(func):
        """
        Este decorador hace la resolucion de un nombre de dominio
        a direccion IPv4 para ser procesada de manera mas sencilla
        """
        def wrapper(self, *args, **kwargs):
            try:
                nombre = self.__ip
                direccion_ip = socket.gethostbyname(nombre)
                print("La direccion ip de " + nombre + " es: " + direccion_ip)
                fun = func(self, *args, **kwargs)
                return fun
            except socket.gaierror:
                print("No fue posible resolver la direccion de: " + nombre)
        return wrapper
    
    @resolver_ip
    def escanerRango(self, inicio = 1, fin = 10000, tiempo = 0.01):
        """
        Realiza un escaneo de los puertos en el rango especificado y devuelve los resultados
        recibe 3 argumentos que seon los siguietes:
        inicio -> puerto inicial por ejemplo puerto 21
        fin -> puerto final a escanear
        tiempo -> tiempo de espera entre cada solicitud, como recomendacion 
                  los tiempo superiores a 1 seg generan resultados mas confiables
        """
        resultados = []  # Almacena los resultados como una lista de tuplas (puerto, servicio)
        contador_a = 0  # Contador de puertos abiertos
        contador_f = 0  # Contador de puertos filtrados
        contador_c = 0  # Contador de puertos cerrados

        total_puertos = fin - inicio + 1

        with tqdm(total = total_puertos, desc = "Escaneando puertos", ascii = True) as barra_de_carga:
            with self.__sock as sock:
                try:
                    for puerto in range(inicio, fin + 1):
                        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        sock.settimeout(tiempo)
                        resultado = sock.connect_ex((self.__ip, puerto))

                        if resultado == 0:
                            servicio = socket.getservbyport(puerto)  # Obtiene el nombre del servicio asociado al puerto
                            resultados.append((puerto, servicio))
                            contador_a += 1
                            barra_de_carga.update(1)
                        elif resultado == 11:
                            contador_f += 1
                            barra_de_carga.update(1)
                        else:
                            contador_c += 1
                            barra_de_carga.update(1)

                        barra_de_carga.update(1)

                    print("\nPuertos abiertos %s 😈" % (contador_a))
                    print("Puertos filtrados %s 💀" % contador_f)
                    print("Puertos cerrados %s 😒" % contador_c)

                except ConnectionError as e:
                    print("No fue posible establecer la conexión: %s" % e)
                except Exception as e:
                    print("Error inesperado: %s" % e)
                except KeyboardInterrupt:
                    print("El programa fue detenido por el usuario")
                finally:
                    barra_de_carga.close()  # Cierra la barra de progreso

        print("\nPuertos abiertos:")
        for r in resultados:
            r = list(r)
            r = " <-> ".join(map(str, r))
            print(r)    

    ###############################
    # escanea puertos especificos # 
    ###############################
    @resolver_ip
    def escanearPuertos(self, ports, tiempo):
        """
        Este metodo escanea puertos especificados por el usuario
        recibe dos argumentos posicionales que son los siguientes:
        ports -> los puertos que se van a escanear 
        """        
        print()
        try:
            for port in ports:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.settimeout(tiempo)
                    resultado = sock.connect_ex((self.__ip, port))
                    
                    if resultado == 0:
                        servicio = socket.getservbyport(port)
                        print("Puerto %s abierto <-> %s 😈" % (port, servicio))
                    elif resultado == 11:
                        print("El puerto %s se encuentra filtrado 💀" % (port))
                    else:
                        print("El puerto %s se encuentra cerrado 😒" % (port))
        except socket.error as e:
            print("Error al escanear el puerto %s" % (port))
        except ConnectionRefusedError:
            print("Ocurrio un error en la conexion")
        except KeyboardInterrupt:
            print("Programa detenido por el eusuario")

    ##################################
    # Obtiene la version del ervidor #
    ##################################
    def obtener_version_servidor(self):
        """
        Este metodo se encarga de obtener la version de un servidor web
        no recibe ningun argumento
        """
        try:
            conectar = http.client.HTTPConnection(self.__ip, 80)
            conectar.request("HEAD", "/")
            respuesta = conectar.getresponse()
            version_servidor = respuesta.getheader("Server")
            print("La version del servidor es: %s" % (version_servidor))
        except socket.timeout:
            print("Tiempo de espera agotado")
        except Exception as e:
            print("Ocurrio un error %s" % (e))

class EscanearIps:
    """
    Clase para escanear direcciones IP y puertos.
    
    Atributos:
    - __sock (socket): Socket para el escaneo de puertos.
    """
    def __init__(self):
        """
        Constructor de la clase EscanearIps.
        Inicializa el socket para el escaneo de puertos.
        """
        self.__sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    def escaner(self, ips, ports, tiempo):
        """
        Escanea direcciones IP y puertos especificados.
        Args:
        - ips (list): Lista de direcciones IP a escanear.
        - ports (list): Lista de puertos a escanear.
        - tiempo (float): Tiempo de espera para la conexión en segundos.
        """
        try:
            for ip in ips:
                nombre = ip
                direccion_ip = socket.gethostbyname(nombre)
                print("La direccion ip de %s es %s" % (nombre, direccion_ip))
        except ConnectionError as e:
            print("Error en la conexion %s" % (e))
        print()
        #escaneo de puertos en las direcciones ip
        try:
            for ip in ips:
                for port in ports:
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                        sock.settimeout(tiempo)
                        resultado = sock.connect_ex((ip, port))

                        if resultado == 0:
                            servicio = socket.getservbyport(port)
                            print("El puerto %s en la direccion %s esta abierto y ejecuta el servicio %s" % (port, ip, servicio))
                        elif resultado == 11:
                            print("El puerto %s de la direccion %s se encuentra filtrado" % (port, ip))
                        else:
                            print("El puerto %s se encuentra cerrado" % (port))
                print()
        except KeyboardInterrupt:
            print("El programa fue detenido por el usuario")
        finally:
            self.__sock.close()

###############################
#      prueba del codigo      #
###############################
if __name__ == "__main__":
    def main():
        op = input(">> ")
        if op == "one":
            ip = input("Digite una direccion IPv4: ")
            puerto = int(input("Digite un puerto: "))
            conexion = ConexionSocket(ip, puerto)
            conexion.escan()
        elif op == "range":
            ip = input("Digite una direccion ip: ")
            inicio = int(input("Digite el inicio: "))
            fin = int(input("Digite el final: "))
            tiempo = float(input("Digite el tiempo: "))
            rango = Rango(ip)
            rango.escanerRango(inicio, fin, tiempo)

        elif op == "banner":
            ip = input("Digite una direccion IPv4: ")
            puerto = int(input("Digite un puerto: "))
            ban = ConexionSocket(ip, puerto)
            ban.banner()   
        else:
            print("Error")
    
    try:
        main()
    except KeyboardInterrupt as k:
        print("El programa fue detenido por el usuario")