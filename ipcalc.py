#!/usr/bin/env python3

import argparse
import ipaddress
import sys

def main():
    args = parse_args()

    # Safely parse the network, catching errors
    try:
        network = parse_network(args.address, args.mask_arg)
    except ValueError as e:
        # e.g. "'173.24.4.1/255.255.255.220' does not appear to be..."
        print_error_and_suggestion(str(e), args.address, args.mask_arg)
        sys.exit(1)

    print_key_value_info(network, args)

##############################################################################
#                              Parse Arguments                               #
##############################################################################

def parse_args():
    parser = argparse.ArgumentParser(
        description="A key-value ipcalc-like script with error handling, examples, and hostcount.",
        epilog="""
Examples:
  ipcalc.py -n 192.168.0.1/24
    => Prints only the netmask for this CIDR.
  
  ipcalc.py -npmb --minaddr --maxaddr --addrspace 133.92.150.2/255.255.255.224
    => Prints prefix, netmask, network, broadcast, minaddr, maxaddr, and address space,
       with both decimal and binary columns, for that IPv4 network.

  ipcalc.py --hosts 2001:db8::/64
    => Prints the total usable hostcount for an IPv6 /64.

  ipcalc.py -H 173.24.4.1 255.255.255.220
    => Demonstrates error handling for an invalid netmask.
""",
        formatter_class=argparse.RawTextHelpFormatter
    )

    # Positional arguments
    parser.add_argument(
        "address",
        help="IP address (optionally with /prefix). E.g., '133.92.150.2/24'."
    )
    parser.add_argument(
        "mask_arg",
        nargs="?",
        default=None,
        help="Optional netmask or prefix. E.g., '255.255.255.224' or '27'."
    )

    # Key-value output flags
    parser.add_argument("-p", "--prefix",    action="store_true", help="Print CIDR prefix.")
    parser.add_argument("-n", "--netmask",   action="store_true", help="Print netmask.")
    parser.add_argument("-m", "--network",   action="store_true", help="Print network address.")
    parser.add_argument("-b", "--broadcast", action="store_true", help="Print broadcast address (IPv4 only).")
    parser.add_argument("--minaddr",         action="store_true", help="Print first usable host address (if any).")
    parser.add_argument("--maxaddr",         action="store_true", help="Print last usable host address (if any).")
    parser.add_argument("--addrspace",       action="store_true", help="Print address space (e.g., Internet, Private).")
    parser.add_argument("-H", "--hosts",     action="store_true", help="Print total number of usable IP addresses.")

    return parser.parse_args()

##############################################################################
#                          Parsing the Network                               #
##############################################################################

def parse_network(address, mask_arg):
    """
    If address already contains '/', parse it directly.
    Otherwise, combine 'address' + 'mask_arg'.
    Default to /32 (IPv4) or /128 (IPv6) if none provided.
    Raises ValueError if something is invalid.
    """
    if "/" in address:
        # e.g. "1.2.3.4/24"
        return ipaddress.ip_network(address, strict=False)
    else:
        if mask_arg:
            combined = f"{address}/{mask_arg.lstrip('/')}"
            return ipaddress.ip_network(combined, strict=False)
        else:
            ip_obj = ipaddress.ip_address(address)
            if isinstance(ip_obj, ipaddress.IPv4Address):
                return ipaddress.ip_network(f"{address}/32", strict=False)
            else:
                return ipaddress.ip_network(f"{address}/128", strict=False)

##############################################################################
#                 Printing Key-Value Output (Decimal + Binary)              #
##############################################################################

def print_key_value_info(network, args):
    """
    Collect the requested fields, align decimal and binary columns if IPv4,
    and print them in key-value style.
    """
    is_ipv4 = isinstance(network.network_address, ipaddress.IPv4Address)
    prefix = network.prefixlen

    # We'll collect a list of (FIELD, decimal_str, binary_str).
    lines = []

    # 1) PREFIX
    if args.prefix:
        lines.append(("PREFIX", str(prefix), None))

    # 2) NETMASK
    if args.netmask:
        netmask_str = str(network.netmask)
        bin_str = ipv4_to_dotted_binary(network.netmask) if is_ipv4 else None
        lines.append(("NETMASK", netmask_str, bin_str))

    # 3) NETWORK
    if args.network:
        net_str = str(network.network_address)
        net_bin = ipv4_to_dotted_binary(network.network_address) if is_ipv4 else None
        lines.append(("NETWORK", net_str, net_bin))

    # 4) BROADCAST (IPv4 only)
    if args.broadcast and is_ipv4:
        bc_str = str(network.broadcast_address)
        bc_bin = ipv4_to_dotted_binary(network.broadcast_address)
        lines.append(("BROADCAST", bc_str, bc_bin))

    # 5) MINADDR / MAXADDR
    host_min, host_max, host_count = compute_host_range(network)
    if args.minaddr and host_min:
        bin_str = ipv4_to_dotted_binary(ipaddress.ip_address(host_min)) if is_ipv4 else None
        lines.append(("MINADDR", host_min, bin_str))
    if args.maxaddr and host_max:
        bin_str = ipv4_to_dotted_binary(ipaddress.ip_address(host_max)) if is_ipv4 else None
        lines.append(("MAXADDR", host_max, bin_str))

    # 6) ADDRSPACE
    if args.addrspace:
        space_str = classify_address_space(network)
        lines.append(("ADDRSPACE", f"\"{space_str}\"", None))

    # 7) HOSTCOUNT (the new option!)
    if args.hosts:
        if host_count is None:
            # That means we're in IPv6. Let's compute 2^(128 - prefix).
            if prefix >= 128:
                # single IP
                lines.append(("HOSTCOUNT", "1", None))
            else:
                host_count_str = f"2^({128 - prefix}) = {2**(128 - prefix)}"
                lines.append(("HOSTCOUNT", host_count_str, None))
        else:
            # host_count is an int from IPv4 logic
            lines.append(("HOSTCOUNT", str(host_count), None))

    # If user didn't request anything, do nothing
    if not lines:
        return

    # Align columns so that "FIELD=DECIMAL" is the same width across lines
    left_texts = [f"{field}={dec_str}" for (field, dec_str, bin_str) in lines]
    max_len = max(len(t) for t in left_texts)

    for (field, dec_str, bin_str) in lines:
        left_text = f"{field}={dec_str}"
        if bin_str is None:
            # IPv6 or no binary
            print(left_text)
        else:
            # Align the binary
            print(f"{left_text:<{max_len}}  {bin_str}")
    print()

##############################################################################
#                            Helper Functions                                #
##############################################################################

def ipv4_to_dotted_binary(ipv4_addr):
    """
    E.g. 133.92.150.31 => 10000101.01011100.10010110.00011111
    """
    bits = f"{int(ipv4_addr):032b}"
    return ".".join(bits[i:i+8] for i in range(0, 32, 8))

def compute_host_range(network):
    """
    Returns (host_min, host_max, host_count).
      - host_count is an integer for IPv4, or None for IPv6.
      - For IPv4 /0-30 => hosts = all addresses minus network and broadcast
      - /31 => 0 (often used for point-to-point)
      - /32 => 1
      - For IPv6 => host_min=network_address, host_max=broadcast_address, host_count=None
    """
    is_ipv4 = isinstance(network.network_address, ipaddress.IPv4Address)
    pfx = network.prefixlen

    if is_ipv4:
        if pfx < 31:
            hosts = list(network.hosts())
            if len(hosts) >= 2:
                return (str(hosts[0]), str(hosts[-1]), len(hosts))
            elif len(hosts) == 1:
                return (str(hosts[0]), str(hosts[0]), 1)
            else:
                return (None, None, 0)
        elif pfx == 31:
            return (None, None, 0)
        elif pfx == 32:
            return (None, None, 1)
        else:
            return (None, None, 0)
    else:
        # IPv6 => no simple "host" range in the same sense, but we set host_count=None
        host_min = str(network.network_address)
        host_max = str(network.broadcast_address)
        return (host_min, host_max, None)

def classify_address_space(network):
    """
    For IPv4 => 'Private' or 'Internet'.
    For IPv6 => 'Global Unicast', 'Link-Local', etc.
    """
    addr = network.network_address
    if isinstance(addr, ipaddress.IPv4Address):
        if addr.is_private:
            return "Private"
        else:
            return "Internet"
    else:
        # IPv6
        if addr.is_loopback:
            return "Loopback"
        elif addr.is_link_local:
            return "Link-Local"
        elif addr.is_private:
            return "Unique Local"
        else:
            return "Global Unicast"

##############################################################################
#                Error Handling and Suggestion Logic                         #
##############################################################################

def print_error_and_suggestion(err_message, address, mask_arg):
    """
    Print a user-friendly error if the address + mask is invalid.
    Additionally, if the netmask is non-contiguous, suggest a correct mask.
    """
    print(f"Error: {err_message}\n")

    # Check if user typed a non-contiguous mask in IPv4
    if mask_arg and "." in mask_arg:
        # Possibly user typed a mask like 255.255.255.220
        if not is_contiguous_netmask(mask_arg):
            print(f"Hint: '{mask_arg}' seems to be a non-contiguous netmask.")
            possible_suggestions = suggest_nearest_cidr_masks(mask_arg)
            if possible_suggestions:
                print("Possible CIDR netmasks:")
                for s in possible_suggestions:
                    print(f"  {s}")
            print()
    print("Please check your input or use a valid CIDR netmask (e.g. /24 or 255.255.255.0).")

def is_contiguous_netmask(mask_str):
    """
    Return True if mask_str is a valid contiguous IPv4 mask (like 255.255.255.224).
    """
    try:
        mask_ip = ipaddress.ip_address(mask_str)
        if not isinstance(mask_ip, ipaddress.IPv4Address):
            return False
    except ValueError:
        return False

    int_val = int(mask_ip)
    # We'll brute force check against all valid netmasks (0..32 bits)
    possible_nets = [0xffffffff << x & 0xffffffff for x in range(33)]
    return int_val in possible_nets

def suggest_nearest_cidr_masks(bad_mask):
    """
    Return a list of suggested valid netmasks near the user's invalid mask.
    e.g. if user typed 255.255.255.220, we might suggest /27 => 255.255.255.224
    We'll just produce the top 3 prefix matches from /1.. /32.
    """
    try:
        bad_ip = ipaddress.ip_address(bad_mask)
        if not isinstance(bad_ip, ipaddress.IPv4Address):
            return None
        bad_int = int(bad_ip)
    except ValueError:
        return None

    # Build all possible netmasks from /1.. /32
    suggestions = []
    for prefix in range(1, 33):
        nm_int = (0xffffffff << (32 - prefix)) & 0xffffffff
        suggestions.append((prefix, nm_int))

    # Sort by absolute distance to the user's mask
    suggestions.sort(key=lambda x: abs(x[1] - bad_int))

    # We'll just return the top 3
    top_3 = suggestions[:3]
    out = []
    for (pfx, nm_int) in top_3:
        nm_str = str(ipaddress.IPv4Address(nm_int))
        out.append(f"/{pfx} => {nm_str}")
    return out

if __name__ == "__main__":
    main()
