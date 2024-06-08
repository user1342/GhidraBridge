<p align="center">
    <img width=100% src="banner.png">
  </a>
</p>
<p align="center"> 🤖 GhidraBridge: Automate Ghidra Tasks with Ease 🛠️ </p>

<div align="center">

![GitHub contributors](https://img.shields.io/github/contributors/user1342/GhidraBridge)
![GitHub Repo stars](https://img.shields.io/github/stars/user1342/GhidraBridge?style=social)
![GitHub watchers](https://img.shields.io/github/watchers/user1342/GhidraBridge?style=social)
![GitHub last commit](https://img.shields.io/github/last-commit/user1342/GhidraBridge)
<br>

</div>

GhidraBridge is a Python interface for automating Ghidra tasks. It allows users to generate and run scripts that interact with Ghidra, enabling decompilation, cross-referencing, and function analysis in a streamlined manner.
* **🔬 Function Analysis:** Automate the process of retrieving function addresses, names, and references.
* **🛠️ Ghidra Integration:** Leverage Ghidra's powerful decompilation capabilities directly from Python scripts.

# ⚙️ Setup

## System Requirements
GhidraBridge requires [Ghidra](https://ghidra-sre.org/) to be installed and accessible. Ensure that `analyzeHeadless` is available in your environment.

**GhidraBridge has been tested on Windows 11; however, it should be compatible with Unix and other systems.**

## Dependencies

Python dependencies can be found in the `requirements.txt` file:

```
pip install git+https://github.com/user1342/GhidraBridge.git
```

# 🏃 Running

To utilize GhidraBridge, follow the instructions below:

### Generate and Run Scripts
Generate Ghidra scripts for various analysis tasks and execute them.

## Retrieve Decompilation For A Given Function

```python
from ghidrabridge.ghidra_bridge import GhidraBridge

bridge = GhidraBridge()
script = bridge.generate_decom_for_function("main")
bridge.run_string_script_on_binary(script, "<path-to-binary>")
```

## Retrieve Cross References For A Function Name
```python
from ghidrabridge.ghidra_bridge import GhidraBridge

bridge = GhidraBridge()
cross_references_script = bridge.generate_get_cross_references_to_function_name("main")
bridge.run_string_script_on_binary(cross_references_script, "<path-to-binary>")
```

## Generate Function Address by Name
```python
from ghidrabridge.ghidra_bridge import GhidraBridge

bridge = GhidraBridge()
function_address_script = bridge.generate_get_function_address_by_name("main")
bridge.run_string_script_on_binary(function_address_script, "<path-to-binary>")
```

## Generate Function Names and Addresses
```python
from ghidrabridge.ghidra_bridge import GhidraBridge

bridge = GhidraBridge()
function_names_addresses_script = bridge.generate_get_function_names_and_address()
bridge.run_string_script_on_binary(function_names_addresses_script, "<path-to-binary>")
```

## Generate Function Name by Address
```python
from ghidrabridge.ghidra_bridge import GhidraBridge

bridge = GhidraBridge()
function_name_by_address_script = bridge.generate_get_a_function_name_by_address("0x00401000")
bridge.run_string_script_on_binary(function_name_by_address_script, "<path-to-binary>")
```

## Check if Ghidra Project Exists
```python
from ghidrabridge.ghidra_bridge import GhidraBridge

bridge = GhidraBridge()
project_exists = bridge._check_if_ghidra_project_exists("<project-folder>", "<project-name>")
print(f"Project exists: {project_exists}")
```

## Start Headless with Script
```python
from ghidrabridge.ghidra_bridge import GhidraBridge

bridge = GhidraBridge()
bridge.start_headless_with_script("<path-to-binary>", "<path-to-script>")
```

## Decompile Binary's Functions
```python
from ghidrabridge.ghidra_bridge import GhidraBridge

bridge = GhidraBridge()
bridge.decompile_binaries_functions("<path-to-binary>", "<decom-folder>")
```

## Decompile All Binaries in Folder
```python
from ghidrabridge.ghidra_bridge import GhidraBridge

bridge = GhidraBridge()
bridge.decompile_all_binaries_in_folder("<path-to-folder>", "<decom-folder>")
```

# 🙏 Contributions
GhidraBridge is an open-source project and welcomes contributions from the community. If you would like to contribute to GhidraBridge, please follow these guidelines:

- Fork the repository to your own GitHub account.
- Create a new branch with a descriptive name for your contribution.
- Make your changes and test them thoroughly.
- Submit a pull request to the main repository, including a detailed description of your changes and any relevant documentation.
- Wait for feedback from the maintainers and address any comments or suggestions (if any).
- Once your changes have been reviewed and approved, they will be merged into the main repository.

# ⚖️ Code of Conduct
GhidraBridge follows the Contributor Covenant Code of Conduct. Please make sure to review and adhere to this code of conduct when contributing to GhidraBridge.

# 🐛 Bug Reports and Feature Requests
If you encounter a bug or have a suggestion for a new feature, please open an issue in the GitHub repository. Please provide as much detail as possible, including steps to reproduce the issue or a clear description of the proposed feature. Your feedback is valuable and will help improve GhidraBridge for everyone.

# 📜 License
GNU General Public License v3.0