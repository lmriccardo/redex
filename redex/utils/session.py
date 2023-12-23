from dataclasses import dataclass, field


@dataclass
class Session(object):
    s_rhost          : str  = "192.168.1.68" # "0.0.0.0"
    s_rport          : int  = 2375
    s_name           : str  = "container"
    s_names          : list = field(default_factory=list)
    s_image          : str  = "ubuntu:latest"
    s_lhost          : str  = "0.0.0.0"
    s_lport          : str  = 4444
    s_privileged     : bool = True
    s_autoremove     : bool = True
    s_networkdisab   : bool = False
    s_command        : str  = "revshell"
    s_exploit        : str  = "/bash/privesc/mount_host_fs"
    s_exposedports   : dict = field(default_factory=dict)
    s_networkmode    : str  = "bridge"
    s_pidmode        : str  = "host"


@dataclass
class ContainerDatas(object):
    c_default : dict = field(default_factory=dict)