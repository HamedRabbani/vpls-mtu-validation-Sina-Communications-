Target:

The goal of this project is to identify packets within a network capture taken between two PEs in a VPLS network and to verify,
via an automated test,whether the Layer 2 MTU of the VPLS service packets is 1500.


NOTE:
With each commit, the README file will also be updated to reflect what took place during that stage.
----------------------------------------------------------------------------------------------------
Simply put, the program performs these steps:

It reads the capture file.
It reassembles the TCP communication packets.
It identifies BGP messages within the TCP streams.
It examines the UPDATE messages.
It extracts information regarding VPLS and the advertised MTU.
It saves the result to a JSON file for later review.

-----------------------------------------------------------------------------------------------------

Tools used:

Python: For writing the program
Scapy: For reading PCAP/PCAPNG files
pytest: For running automated tests
-------------------------------------------------------


Running on Windows:

Run the commands in PowerShell from the project's root folder.
-------------------------------------------------------

Activating the virtual environment

If the virtual environment has already been created, you simply need to activate it. The name of the virtual environment on your system might differ.

.\.venv\Scripts\Activate.ps1

If you do not yet have a virtual environment, run these commands:

python -m venv .venv
.\.venv\Scripts\Activate.ps1

2. Installing the necessary libraries
python -m pip install --upgrade pip
python -m pip install scapy pytest

--------------------------------------------------------------

Running Tests:
To run the automated tests, execute this command:

python -m pytest -v


Run this from the project's root directory:

python scripts/inspect_bgp_mtu.py

The output report is saved at this path:

reports/bgp_vpls_mtu.json


-----------------------------------------------------

Results recorded up to this stage:
In one of the previous runs, the following results were reported:

Item:                                          	Result:

Number of packets read                      	4,897
BGP UPDATE messages processed	                 26
VPLS-related messages                            18
Extracted MTU values ​​        	              1500 and 9000
Successful tests	                             6

-------------------------------------------------------------

Project Limitations:
-The program analyzes the information contained within the capture file.
-The MTU advertised in BGP is not necessarily equal to the operational MTU of the entire path.
-This tool does not, on its own, test the actual performance of the VPLS service.
-Unprocessed messages and the NLRI format must be examined before drawing final conclusions.



