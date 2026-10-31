"""Pinned Cowrie lab profile: only the command modules needed for our demo.

Mounted over cowrie.commands.__init__; network commands resolve to canned stubs.
Do not expand this list without inspecting the pinned module's runtime behavior.
"""
command_modules = [
    "base", "bash", "busybox", "cat", "chmod", "env", "find", "fs",
    "ls", "printf", "uname", "lab_network",
]
