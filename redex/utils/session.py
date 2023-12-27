from dataclasses import dataclass, field
from redex.data.exploit import ExploitHandler


@dataclass
class Session(object):
    s_rhost        : str            = "192.168.1.68" # "0.0.0.0"
    s_rport        : int            = 2375
    s_name         : str            = "container"
    s_names        : list           = field(default_factory=list)
    s_image        : str            = "ubuntu:latest"
    s_lhost        : str            = "192.168.1.140" # 0.0.0.0
    s_lport        : str            = 4444
    s_privileged   : bool           = True
    s_autoremove   : bool           = True
    s_networkdisab : bool           = False
    s_command      : str            = "revshell"
    s_exploit      : str            = "BASH_PRIVESC_MOUNT_HOST_FS"
    s_exposedports : dict           = field(default_factory=dict)
    s_networkmode  : str            = "bridge"
    s_pidmode      : str            = "host"
    s_exploits     : ExploitHandler = None


# This class has only one attribute. However it can be
# augmented by using the setdata command and thus
# creating new attribute using setattr.
@dataclass
class ContainerDatas(object):
    c_default : dict = field(default_factory=dict)