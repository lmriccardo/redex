import socket
import rich

from redex.utils.thread import Threading
from redex.data.ports import DEFAULT_PORTS_JSON
from typing import Optional
from rich.table import Table


class PortScanner(object):
    """**Multithread Port Scanner**

    Multithread automatic port scanner. It scans for a number of ports
    and select only those that are open. To check if a port is open,
    a fake connection is established with the victim machine. If any
    answer returns withing a timeout threshold, than the victim is 
    reachable through that port, otherwise it is not.

    Attributes
    ----------
    open_ports : List[int]
        A list of all the open ports found during the scanning
    console : rich.console.Console
        The handler to the rich console to print out some information
    """
    def __init__(self, console: rich.console.Console) -> None:
        self.open_ports = []
        self.console = console

    @staticmethod
    def get_host_ip_addr(host: str) -> Optional[str]:
        """
        Returns the IP address given the Host name. For example
        given "google.com" it returns '216.58.204.142'.

        Parameters
        ----------
        host : str
            The name of the host for which you want the IP

        Returns
        -------
        Optional[str]
            The corresponding IP or None, if the host does not exists.
        """
        try:
            return socket.gethostbyname(host)
        except socket.gaierror:
            return None

    def scan(self, ip: str, port: str) -> None:
        """
        Controls if a specified port is open or not by trying
        to connect to it. If the returned status is 0 then
        the port is open, otherwise it is not.

        Parameters
        ----------
        ip : str
            The IP you want to connect to
        port : str
            The port to check
        """
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1.0) # set the timeout for the connection
        port = int(port)
        conn_status = sock.connect_ex((ip, port))
        if conn_status == 0:
            self.open_ports.append(port)
        
        sock.close()

    def show_completition_message(self) -> None:
        """
        Shows the final message. If there is at least one open port it shows a 
        table with all the open ports, what service they should represent and 
        if they are open or not. On the other hand, if no open ports have been 
        found it shows the corresponding message.
        """
        if self.open_ports:
            self.console.print("Scan completed. Open Ports: ", style="bold green")

            t = Table(show_header=True, header_style="bold blue")
            t.add_column("PORT", style="green")
            t.add_column("STATE", style="green", justify="center")
            t.add_column("SERVICE", style="green")
            
            for port in self.open_ports:
                t.add_row(str(port), "OPEN", DEFAULT_PORTS_JSON[str(port)])
            
            self.console.print(t)
        else:
            self.console.print(
                "No Open Ports Found on Target.", style="bold magenta")

    def run(self, host: str) -> bool:
        """
        Run the port scanning using a multithreading approach.

        Parameters
        ----------
        host : str
            The host name that you would like to scan
        
        Returns
        -------
        bool
            Returns True if the scan has ended successfully,
            False if there was an error during the process.
        """
        ip = self.get_host_ip_addr(host)
        if not ip: return False

        self.console.print(f"[*] Scanning: [bold blue]{ip}[/bold blue]")

        try:
            ip_port_mapping = [ (ip, x) for x in DEFAULT_PORTS_JSON.keys() ]
            func = lambda x: self.scan(*x)
            Threading.threadpool_executor(
                func, ip_port_mapping, len(DEFAULT_PORTS_JSON.keys())
            )
        except KeyboardInterrupt: ...
        except Exception: return False

        self.show_completition_message()
        return True