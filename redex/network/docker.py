import requests
import socket
import rich
import json

from typing import Dict, Any, List


def send_request_listimages(rhost: str, rport: int) -> requests.Response:
    """
    Send an HTTP request over an open TCP connection towards a remote host
    via the specified input port to list all images. It returns a JSON 
    formatted response with all the informations required for the computation.

    References
    ----------
    Docker Engine API Documentation Version 1.42
    https://docs.docker.com/engine/api/v1.42/#tag/Image/operation/ImageList

    Parameters
    ----------
    rhost : str
        The IP of the remote host
    rport : int
        The port via which the connection occurs

    Returns
    -------
    requests.Response
        The HTTP response from the docker daemon
    """
    return requests.get(f"http://{rhost}:{rport}/images/json") 


def socket_connect(sock: socket.socket, rhost: str, rport: int) -> bool:
    """
    Try to connect to a remote host via a socket

    Parameters
    ----------
    sock : socket.socket
        The socket used to test the connection towards a remote host
    rhost : str
        The IP address of the remote host you would like to connect
    rport : int
        The port number through which the connection should be made

    Returns
    -------
    bool
        True if the connection is successfull, False otherwise.
    """
    try:
        sock.connect((rhost, rport))
        return True
    except socket.gaierror:
        return False
    

def send_request_pull_image(rhost: str, rport: int, image: str) -> None:
    """
    Send a HTTP POST request over a TCP connection towards a remote host
    via the given input port to pull an image in the remote host. At each
    step of download a message showing the progress will be printed. Notice
    that the request is sent using a Socket, since we would like to use
    an async method. Using the `requests.post`, instead, we have to wait
    until the end of the process.

    Refereces
    ---------
    Docker Engine API Documentation Version 1.42
    https://docs.docker.com/engine/api/v1.42/#tag/Image/operation/ImageCreate

    Parameters
    ----------
    rhost : str
        The IP of the remote host
    rport : int
        The port via which the connection occurs
    image : str
        The name, and optionally the tag, of the image to pull
    """
    # Create the HTTP request to sent to the Docker Daemon
    request = f"POST /images/create?fromImage={image} HTTP/1.1\r\n" + \
              f"Host:{rhost}:{rport}\r\n\r\n"    + \
               "Content-Type: application/json\r\n"
    
    encoded_req = request.encode()

    # Setting up the socket that will be used to sent the request
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    connected = socket_connect(sock, rhost, rport)
    if not connected: return

    # Let's send the encoded request and wait until the
    # entire image has been downloaded into the victim host
    console = rich.console.Console(color_system="truecolor")
    try:
        sock.send(encoded_req)
        
        # Receives the first 4096 bytes of results. They are enough
        # for what we need to check if the image has been downloaded
        response = sock.recvmsg(4096)
        progress = json.loads(response[0].decode().split("\r\n")[10])

        # Let's loop until we finished
        while "Downloaded" not in progress["status"]:
            response = sock.recvmsg(4096)
            progress = json.loads(response[0].decode().split("\r\n")[1])

            if "progress" in progress:
                console.print(
                    f"[*] Pulling: [magenta]{progress['progress']}[/magenta]",
                    end="\r"
                )

        print("\n")
    except BrokenPipeError:
        console.print("[*] Command failed!", style="bold red")

    sock.close()


def send_request_create_container(
    rhost: str, rport: int, container_name: str, container_data: Dict[str, Any]
) -> None:
    """
    Send a HTTP POST request over a TCP connections towards a remote host
    via a given input port number to create a new container.

    References
    ----------
    Docker Engine API Documentation Version 1.42
    https://docs.docker.com/engine/api/v1.42/#tag/Container/operation/ContainerCreate

    Parameters
    ----------
    rhost : str
        The IP of the remote host
    rport : int
        The port via which the connection occurs
    container_name : str
        The name of the container that will be created
    container_data : Dict[str, Any]
        The JSON Payload of the request containing all the settings for the container
    """
    addr  = f"{rhost}:{rport}"
    query = f"name={container_name}"
    console = rich.console.Console(color_system="truecolor")
    
    # Let's create a POST request to create a specified container
    # The data that the request should contain is in the DATA variable
    response = requests.post(
        f"http://{addr}/containers/create?{query}", json=container_data['create']
    )

    # Check if the response code is 201
    if response.status_code != 201:
        console.print(
            f"[*] [red]Error: {response.json()['message']}[/red]"
        )
        raise Exception
    
    console.print(
        f"[*] [green]Container Created[/green] ID: {response.json()['Id']}"
    )


def send_request_start_container(rhost: str, rport: int, container_name: str) -> None:
    """
    Send a HTTP POST request over a TCP connection towards the remote host
    via a specified input port, to start a created container. 

    References
    ----------
    Docker Engine API Documentation Version 1.42
    https://docs.docker.com/engine/api/v1.42/#tag/Container/operation/ContainerStart

    Parameters
    ----------
    rhost : str
        The IP of the remote host
    rport : int
        The port via which the connection occurs
    container_name : str
        The name of the container that will be started. Note that
        a container with this name must have been created.
    """
    addr  = f"{rhost}:{rport}"
    console = rich.console.Console(color_system="truecolor")

    response = requests.post(f"http://{addr}/containers/{container_name}/start")
    if response.status_code != 204:
        console.print(f"[*] [red]Error: {response.json()['message']}[/red]")
        raise Exception
    

def send_request_stop_container(rhost: str, rport: int, container_name: str) -> None:
    """
    Send a HTTP POST request over a TCP connection towards the remote host
    via a specified input port, to stop a running container. 

    References
    ----------
    Docker Engine API Documentation Version 1.42
    https://docs.docker.com/engine/api/v1.42/#tag/Container/operation/ContainerStop

    Parameters
    ----------
    rhost : str
        The IP of the remote host
    rport : int
        The port via which the connection occurs
    container_name : str
        The name of the container that will be started. Note that
        a container with this name must have been created.
    """
    addr  = f"{rhost}:{rport}"
    console = rich.console.Console(color_system="truecolor")

    response = requests.post(f"http://{addr}/containers/{container_name}/stop")
    if response.status_code != 204:
        console.print(f"[*] [red]Error: {response.json()['message']}[/red]")
        raise Exception

    
def extrapolate_information_from_json(data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Extrapolate a number of useful informations from a JSON returned
    by response to a GET requests done by the tool to the remote host.
    This function is explicitly used only when we are requesting
    to list all the containers active or not in the remote machine.

    Parameters
    ----------
    data : Dict[str, Any]
        The actual content of the JSON formatted data

    Returns
    -------
    Dict[str, Any]
        A bunch of useful informations about the data in the JSON
    """
    # Takes general informations
    container_id = data["Id"]
    container_name = data["Names"][0]
    base_image = data["Image"]
    command = data["Command"]
    state = data["State"]

    # Takes exposed ports
    _available_ports = data["Ports"]
    ports = {"Ports": []}
    for port in _available_ports:
        ip = "" if "IP" not in port else port["IP"]
        priv_port = "" if "PrivatePort" not in port else port["PrivatePort"]
        publ_port = "" if "PublicPort" not in port else port["PublicPort"]
        port_str = f"{publ_port} -> {priv_port}(type={port['Type']},ip={ip})"
        ports["Ports"].append(port_str)

    # Takes labels
    _available_labels = data["Labels"]
    labels = {"Labels": []}
    for k, v in _available_labels.items():
        label_str = f"{k.split('.')[-1]}={v}"
        labels["Labels"].append(label_str)

    # Takes network settings
    _available_networks = data["NetworkSettings"]["Networks"]
    networks = dict()
    for net_k, net_v in _available_networks.items():
        networks[net_k] = {}
        networks[net_k]["NetworkID"] = net_v["NetworkID"]
        networks[net_k]["EndpointID"] = net_v["EndpointID"]
        networks[net_k]["Gateway"] = net_v["Gateway"]
        networks[net_k]["IPAddress"] = net_v["IPAddress"]
        networks[net_k]["MacAddress"] = net_v["MacAddress"]

    # Takes mount points
    _available_mount_points = data["Mounts"]
    mounts = {"Mounts": []}
    for mount in _available_mount_points:
        mount_str = f"{mount['Source']} -> {mount['Destination']}(type={mount['Type']})"
        mounts["Mounts"].append(mount_str)

    return {
        "Id"       : container_id,
        "Name"     : container_name,
        "Image"    : base_image,
        "Command"  : command,
        "State"    : state,
        "Ports"    : ports["Ports"],
        "Labels"   : labels["Labels"],
        "Networks" : networks,
        "Mounts"   : mounts["Mounts"]
    }


def send_request_list_containers(rhost: str, rport: int, data: Dict[str, Any]) -> requests.Response:
    """
    Send a HTTP GET request over a TCP connection towards a remote host
    via the given input port, to list all the container running or in any
    other current state, on the remote machine.

    References
    ----------
    Docker Engine API Documentation Version 1.42
    https://docs.docker.com/engine/api/v1.42/#tag/Container/operation/ContainerList

    Parameters
    ----------
    rhost : str
        The IP of the remote host
    rport : int
        The port via which the connection occurs
    data : Dict[str, Any]
        The JSON Payload to send over the HTTP request to filter the containers
    
    Returns
    -------
    requests.Response
        The HTTP response snet by the remote host
    """
    addr  = f"{rhost}:{rport}"
    response = requests.get(f"http://{addr}/containers/json", params=data)
    console = rich.console.Console(color_system="truecolor")

    if response.status_code != 200:
        console.print(f"[*] [red]Error: {response.json()['message']}[/red]")
        raise Exception
    
    return response


def send_request_remove_containers(rhost: str, rport: int, names: List[str]) -> None:
    """
    Send a HTTP DEL request over a TCP connection towards a remote host
    via the give input port, to remove a number of containers.

    References
    ----------
    Docker Engine API Documentation Version 1.42
    https://docs.docker.com/engine/api/v1.42/#tag/Container/operation/ContainerDelete

    Parameters
    ----------
    rhost : str
        The IP of the remote host
    rport : int
        The port via which the connection occurs
    names : List[str]
        The name of all the containers to remove
    """
    addr = f"{rhost}:{rport}"
    console = rich.console.Console(color_system="truecolor")

    for name in names:
        response = requests.delete(f"http://{addr}/containers/{name}?v=true&force=true")
        if response.status_code != 204:
            console.print(f"[*] [red]Error: {response.json()['message']}[/red]")
            raise Exception
        
        console.print(f"[*] [green]Removed container {name}[/green]")


def send_request_inspect_containers(rhost: str, rport: int, names: List[str]) -> None:
    """
    Send a HTTP DEL request over a TCP connection towards a remote host
    via the give input port, to inspect a number of containers.

    References
    ----------
    Docker Engine API Documentation Version 1.42
    https://docs.docker.com/engine/api/v1.42/#tag/Container/operation/ContainerInspect

    Parameters
    ----------
    rhost : str
        The IP of the remote host
    rport : int
        The port via which the connection occurs
    names : List[str]
        The name of all the containers to inspects
    """
    addr = f"{rhost}:{rport}"
    console = rich.console.Console(color_system="truecolor")

    for name in names:
        response = requests.get(f"http://{addr}/containers/{name}/json")
        if response.status_code != 200:
            console.print(f"[*] [red]Error: {response.json()['message']}[/red]")
            raise Exception
        
        console.print(response.json())


def send_request_create_exec(
    rhost: str, rport: int, exec_data: Dict[str, Any], container_name: str
) -> int | str:
    """
    Send a HTTP POST request over an TCP connection with a remote host
    via the given input port number, to create an execution istance
    for a running container identified with the input container name.

    References
    ----------
    Docker Engine API Documentation Version 1.42
    https://docs.docker.com/engine/api/v1.42/#tag/Exec/operation/ContainerExec

    Parameters
    ----------
    rhost : str
        The IP of the remote host
    rport : int
        The port via which the connection occurs
    exec_data : Dict[str, Any]
        The JSON Payload to send through the request
    container_name : str
        The name of the running container that will execute the instance

    Returns
    -------
    int | str
        The ID of the newly created exec instance.
    """
    addr = f"{rhost}:{rport}"
    console = rich.console.Console(color_system="truecolor")

    response = requests.post(
        f"http://{addr}/containers/{container_name}/exec", json=exec_data
    )
    if response.status_code != 201:
        console.print(f"[*] [red]Error: {response.json()['message']}[/red]")
        raise Exception

    exec_id = response.json()["Id"]
    return exec_id


def send_request_start_exec(
    rhost: str, rport: int, exec_id: str | int, exec_start_data: Dict[str, Any]
) -> None:
    """
    Send a HTTP POST request on a TCP connection towards a remote host
    via the give input port, to start the execution instance previously created.

    Refereces
    ---------
    Docker Engine API Documentation Version 1.42
    https://docs.docker.com/engine/api/v1.42/#tag/Exec/operation/ExecStart

    Parameters
    ----------
    rhost : str
        The IP of the remote host
    rport : int
        The port via which the connection occurs
    exec_id : str | int
        The ID of the execution instance previously created
    exec_start_data : Dict[str, Any]
        The JSON Payload to sent along with the request
    """
    addr = f"{rhost}:{rport}"
    console = rich.console.Console(color_system="truecolor")

    response = requests.post(
        f"http://{addr}/exec/{exec_id}/start", json=exec_start_data["exec_start"]
    )
    if response.status_code != 200:
        console.print(f"[*] [red]Error: {response.text}[/red]")
        raise Exception

    console.print("[*] [green]Result[/green]")
    console.print(response.text)