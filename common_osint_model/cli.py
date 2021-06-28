import io
import json
from argparse import ArgumentParser

from common_osint_model import *


def convshodan() -> None:
    """
    Converts a JSON file with shodan data to the common data model
    """
    args = parse_args()
    if args.flatten:
        convert(args.filepath, from_shodan_flattened, args.indent)
    else:
        convert(args.filepath, from_shodan, args.indent)


def convcensys():
    """
    Converts a JSON file with shodan data to the common data model
    """
    args = parse_args()
    if args.flatten:
        convert(args.filepath, from_censys_ipv4_flattened, args.indent)
    else:
        convert(args.filepath, from_censys_ipv4, args.indent)


def convcensyscert():
    """
    Converts a JSON file with censys certificate data to the common data model
    """
    args = parse_args()
    if args.flatten:
        convert(args.filepath, from_censys_certificates_flattened, args.indent)
    else:
        convert(args.filepath, from_censys_certificates, args.indent)


def convcensys2():
    """
    Converts a JSON file with censys search 2.0 data to the common data model
    """
    args = parse_args()
    if args.flatten:
        convert(args.filepath, from_censys_flattened, args.indent)
    else:
        convert(args.filepath, from_censys, args.indent)


def convcert():
    """
    Converts a certificate PEM file into the common data model
    """
    args = parse_args()
    if args.flatten:
        d = from_x509_pem_flattened(open(args.filepath).read())
    else:
        d = from_x509_pem(open(args.filepath).read())
    print(json.dumps(d, indent=args.indent))


def parse_args():
    parser = ArgumentParser()
    parser.add_argument("filepath", type=str, help="JSON file to read from")
    parser.add_argument(
        "-F", "--flatten", action="store_true", help="Flatten the output"
    )
    parser.add_argument(
        "-I", "--indent", type=int, default=4, help="Indent of the JSON output"
    )
    return parser.parse_args()


def convert(filepath: str, f, indent: int = 4) -> None:
    with io.open(filepath, "r") as file:
        data = json.loads(file.read())
        print(json.dumps(f(data), indent=indent))
