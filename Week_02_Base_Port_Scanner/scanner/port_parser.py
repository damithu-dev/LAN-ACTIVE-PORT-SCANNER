"""
LAN Scanner - Week 2: Port List Parser & Sanitizer
Author: Damithu (Quality Assurance & Solution Architecture Lead)
"""

import re
from typing import List
from .common_ports import TOP_100_PORTS, TOP_1000_PORTS


def parse_ports(spec: str) -> List[int]:
    """
    Parses a user-supplied port specification into a sorted, deduplicated list of valid integers.

    Supported formats:
        - Single port: "80"
        - Comma-separated: "80,22,443,8080"
        - Range: "1-1024" or "8000-8010"
        - Mixed: "22,80-85,443,8080-8082"
        - Profiles: "top100", "top1000", "all" (1-65535)

    Args:
        spec: Port specification string.

    Returns:
        List[int]: Sorted, unique list of valid port numbers (1-65535).

    Raises:
        ValueError: On invalid syntax, out-of-range ports (<1 or >65535), or inverted ranges.
        TypeError: If spec is not a string.
    """
    if not isinstance(spec, str):
        raise TypeError(f"Port specification must be a string, got {type(spec).__name__}")

    cleaned = spec.strip().lower()
    if not cleaned:
        raise ValueError("Port specification cannot be empty")

    # Named port profiles
    if cleaned in ("top100", "top-100", "fast"):
        return list(TOP_100_PORTS)
    if cleaned in ("top1000", "top-1000", "default"):
        return list(TOP_1000_PORTS)
    if cleaned in ("all", "full"):
        return list(range(1, 65536))

    result_ports = set()
    tokens = [t.strip() for t in cleaned.split(",") if t.strip()]

    if not tokens:
        raise ValueError("Invalid port specification: no valid tokens found")

    for token in tokens:
        if "-" in token:
            # Handle range: e.g. "80-85"
            parts = token.split("-")
            if len(parts) != 2:
                raise ValueError(f"Malformed port range '{token}': expected start-end")
            start_str, end_str = parts[0].strip(), parts[1].strip()
            if not (start_str.isdigit() and end_str.isdigit()):
                raise ValueError(f"Port range boundaries must be numeric, got '{token}'")

            start, end = int(start_str), int(end_str)
            if start > end:
                raise ValueError(f"Inverted port range '{token}': start ({start}) cannot exceed end ({end})")
            if not (1 <= start <= 65535 and 1 <= end <= 65535):
                raise ValueError(f"Port range '{token}' exceeds valid port boundaries (1-65535)")

            for p in range(start, end + 1):
                result_ports.add(p)
        else:
            # Handle single port: e.g. "80"
            if not token.isdigit():
                raise ValueError(f"Port token must be numeric, got '{token}'")
            port = int(token)
            if not (1 <= port <= 65535):
                raise ValueError(f"Port {port} is outside valid boundary (1-65535)")
            result_ports.add(port)

    return sorted(list(result_ports))
