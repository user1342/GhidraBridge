from ghidrabridge.ghidra_bridge import GhidraBridge

bridge = GhidraBridge()
#
print(bridge.get_list_of_reachable_functions(r"C:\Users\james\Downloads\linux-static-binaries-master\linux-static-binaries-master\armv8-aarch64 - Copy\pure-authd","FUN_004002c8"))
