import argparse
from contenido.mensaje import mensaje
from contenido.escaner import ConexionSocket, Rango, EscanearIps

def main():
    parser = argparse.ArgumentParser(description = mensaje())
    parser.add_argument("-t", "--target", type = str, help = "Direccion ip o nombre de dominio del objetivo")
    parser.add_argument("-ts", "--targets", type = lambda s: [str(item) for item in s.split(',')], help = "Victima u objetivo")
    parser.add_argument("-p", "--port", type = int, help = "Puerto a escanear")
    parser.add_argument("-rg", "--range", type = str, help = "Rango de puertos a escanear")
    parser. add_argument("-tm", "--time", type = float, default = 0.1, help = "Tiempo entre cada peticion")
    parser.add_argument("-vs", "--version-server", action = "store_true", help = "Obtiene la version del servidor")
    parser.add_argument("-bn", "--banner", action = "store_true", help = "Obtiene el banner del servidor")
    parser.add_argument("-ps", "--ports", help = "Puertos a escanear, separados por comas", type = lambda s: [int(item) for item in s.split(',')])
    args  = parser.parse_args()

    try:
        if args.target and args.port:
            """
            escanea una direccion ip, un puerto especifico y obtinene el banner del servidor si es posible
            """
            if args.banner:
                escaner = ConexionSocket(args.target, args.port)
                escaner.banner()
            else:
                escaner = ConexionSocket(args.target, args.port)
                escaner.escan()

        elif args.target and args.range and args.time:
            """
            ecane un rango una ip y un rango de puertos
            """
            try:
                inicio, fin = map(int, args.range.split("-"))
                escanerRange = Rango(args.target)
                escanerRange.escanerRango(inicio, fin, args.time)
            except ValueError:
                print("El rango proporcionado no es valido")
                return
        
        elif args.target and args.ports and args.time:
            """
            Escanea puertos especificos
            """
            puertosEspecificos = Rango(args.target)
            puertosEspecificos.escanearPuertos(args.ports, args.time)

        elif args.targets and args.ports and args.time:
            escanner = EscanearIps()
            escanner.escaner(args.targets, args.ports, args.time)

        elif  args.target and args.version_server:
            """
            obtiene la version del servidor
            """
            version = Rango(args.target)
            version.obtener_version_servidor()
        
        else:
            print("Argumentos no validos")
    except KeyboardInterrupt:
        print("Programa detenido por el usuario")
    except Exception as e:
        print("Ocurrio un error inesperado %s" % (e))

if __name__ == "__main__":
    try:
        main()
    except NameError:
        print("Ocurrio un error")