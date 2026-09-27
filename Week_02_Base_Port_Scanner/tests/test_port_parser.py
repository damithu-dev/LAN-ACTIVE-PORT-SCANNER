"""
Unit Tests for Port List Parser & Sanitizer
Author: Damithu (QA & Solution Architecture Lead)
"""

import sys
from pathlib import Path
import pytest

# Ensure parent directory is in sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from scanner.port_parser import parse_ports
from scanner.common_ports import TOP_100_PORTS, TOP_1000_PORTS


def test_parse_single_port():
    assert parse_ports("80") == [80]
    assert parse_ports("443") == [443]


def test_parse_comma_separated_ports():
    ports = parse_ports("80, 22, 443, 8080")
    assert ports == [22, 80, 443, 8080]


def test_parse_port_range():
    ports = parse_ports("1-5")
    assert ports == [1, 2, 3, 4, 5]


def test_parse_mixed_specification():
    ports = parse_ports("22, 80-82, 443, 80-81")
    assert ports == [22, 80, 81, 82, 443]


def test_parse_named_profiles():
    assert parse_ports("top100") == TOP_100_PORTS
    assert parse_ports("top1000") == TOP_1000_PORTS
    assert len(parse_ports("all")) == 65535


def test_deduplication_and_sorting():
    raw_input = "443, 80, 22, 80, 443, 22"
    assert parse_ports(raw_input) == [22, 80, 443]


def test_invalid_syntax_handling():
    with pytest.raises(ValueError):
        parse_ports("")

    with pytest.raises(ValueError):
        parse_ports("   ")

    with pytest.raises(ValueError):
        parse_ports("abc")

    with pytest.raises(ValueError):
        parse_ports("80,xyz,443")


def test_out_of_range_handling():
    with pytest.raises(ValueError):
        parse_ports("0")

    with pytest.raises(ValueError):
        parse_ports("65536")

    with pytest.raises(ValueError):
        parse_ports("100-70000")


def test_inverted_range_handling():
    with pytest.raises(ValueError):
        parse_ports("500-100")


def test_invalid_type_rejection():
    with pytest.raises(TypeError):
        parse_ports(12345)
