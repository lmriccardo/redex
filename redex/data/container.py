DEFAULT_CONTAINER_DATA = {
    "create" : {
        "Image" : "ubuntu:latest", "HostConfig" : {
            "Privileged": True,
            "AutoRemove": True,
            "Mounts" : [{
                "Target": "/mnt/fs",
                "Source": "/",
                "Type": "bind",
                "ReadOnly": False
            }],
            "NetworkMode" : "host",
            "PidMode" : "host",
            "PortBindings" : {
                "3000/tcp" : [
                    {
                        "HostPort": "8080"
                    }
                ]
            }
        },
        "NetworkDisabled" : False,
        "Entrypoint": ["tail", "-f", "/dev/null"],
        "OpenStdin" : True,
        "ExposedPorts" : {
            "3000/tcp" : {}
        }
    },
    "exec" : {
        "Cmd" : [
            "/bin/bash", "-c", 
            "{:s}"
        ],
        "AttachStdin" : True,
        "AttachStdout" : True,
        "AttachStderr" : True,
        "Tty" : True,
        "Privileged": True
    },
    "exec_start" : {
        "Tty" : True
    }
}
