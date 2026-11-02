"""Clipboard: OSC 52 (works over SSH and in tmux with set-clipboard on) plus wl-copy/xclip/xsel."""
import base64
import os
import shutil
import subprocess


def copy(text: str) -> str:
    """Copy `text`; return a short description of how."""
    how = []
    try:
        seq = "\033]52;c;" + base64.b64encode(text.encode()).decode() + "\a"
        with open("/dev/tty", "w") as tty:
            tty.write(seq)
            tty.flush()
        how.append("OSC 52")
    except OSError:
        pass
    tools = []
    if os.environ.get("WAYLAND_DISPLAY"):
        tools.append(["wl-copy"])
    if os.environ.get("DISPLAY"):
        tools += [["xclip", "-selection", "clipboard"], ["xsel", "--clipboard", "--input"]]
    for cmd in tools:
        if shutil.which(cmd[0]):
            try:
                subprocess.run(cmd, input=text.encode(), timeout=2, check=True,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                how.append(cmd[0])
                break
            except (subprocess.SubprocessError, OSError):
                continue
    return " + ".join(how) or "nothing (no clipboard available)"
