import argparse
import requests
import plugins
from plugins import utils


def run_scanner(url, selected_modules=None):
    session = requests.Session()

    baseline, reconnaissance = utils.recon(session, url)
    if reconnaissance is None:
        print("Failed to perform reconnaissance on the target.")
        return None
    
    if selected_modules:
        to_run = {k: v for k, v in plugins.REGISTRY.items() if k in selected_modules}
    else:
        to_run = plugins.REGISTRY

    results = {}
    for key, plugin in to_run.items():
        print(f"Running {plugin.name}")
        findings = plugin.run(url, session, baseline, reconnaissance)
        results[plugin.name] = findings
    
    return results


def main():
    parser = argparse.ArgumentParser(description="Modular Vulnerability Scanner")
    
    parser.add_argument("--url", required=True, help="Target URL")
    parser.add_argument("--modules", nargs="*", help="Modules to run")
    parser.add_argument("--list-modules", action="store_true", help="List available modules and exit")

    args = parser.parse_args()

    if args.list_modules:
        print("Available Modules:")
        max_len = max(len(k) for k in plugins.REGISTRY.keys())
        for key, plugin in plugins.REGISTRY.items():
            print(f"{key.ljust(max_len)} : {plugin.description}")
        return

    selected_modules = args.modules if args.modules else None
    results = run_scanner(args.url, selected_modules)
    if results is None:
        return
    print(results)
    print("Scan Results")
    print("PRINT RESULTS") # TODO - MAKE PRINT RESULTS OF SCAN, ALSO SAVE RESULTS AS PDF/JSON/HTML
    return


if __name__ == "__main__":
    main()