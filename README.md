# NetProbe
NetProbe is a tool designed for network probing, parallel transmission, and collection of ICMP packets on the Linux platform.
# Installation
To install and compile the project, follow the steps below:

1. Install the required dependencies:
   ```bash
    sudo apt update
    sudo apt install qt5-qmake qtbase5-dev
    ```
2. Compile the project:
   ```bash
    qmake ping_program.pro
    make
    ```
# Usage
## MLS

This project utilizes the [MLSgen](https://github.com/ymirsky/MLSgen) tool for generating Maximum Length Sequences (MLS). 
For more details on its implementation and usage, please refer to the [MLSgen repository](https://github.com/ymirsky/MLSgen).
## NetProbe
NetProbe is designed for network probing and key generation, where both the probe transmitter and receiver are integrated into a single unit. It allows the sending of ICMP echo requests and collection of round-trip time (RTT) data for key agreement processes.
### Command
```bash
sudo ./ping_program <Target IP> <Probe Sequence Length> <Packet Frequency> <Mode 1=Input Signal 2=Random MLS Generation> <Signal File Source> <Host Identifier> --active|--listen
```
### Parameters:
- \<**Target IP**\>: IP address of the target host.
- \<**Probe Sequence Length**\>: Total number of ICMP echo requests to send.
- \<**Sequence Probe Length**\>: Frequency of packet sending, in packets per second.
- \<**Mode**\>:
    - `1`: Input signal file.
    - `2`: Randomly generate MLS signal.
- \<**Signal File Source**\>:
    - **Mode 1**: Provide the path to the signal file, where each line contains a binary value (1 or 0).This mode is specifically designed to facilitate debugging, allowing the use of predefined signal files for controlled testing and reproducibility of experiments.
        - **Note**: Total packet count must be less than or equal to the number of lines in the signal file. If the packet count exceeds the file length, it may cause issues.
    - **Mode 2**: Provide a string in the format `n{nbits}s{initseed}`.
        - `nbits`: Defines the bit length of the signal sequence, with the sequence length being ![Formula1](/images/MathFormula1.svg).
        - `initseed`: The initial seed for the MLS sequence generation. The same seed will generate the same signal sequence.
        - **Example**: `n10s12`, which generates a signal sequence of length 1023 with an initial seed of 12 (should not exceed ![Formula1](/images/MathFormula1.svg)).
        - In this mode, the <Sequence Probe Length> should match the length of the generated signal.
- \<**Host Identifier**\>: Identifier for the host, used to distinguish different devices.
    - --active：Active mode. Sends ICMP requests and records data.
    - --listen：Listen mode. Responds to incoming ICMP requests from other hosts.

### Example Workflow
1. **Copy NetProbe to Alice and Bob's machines**
   
   Transfer NetProbe to both Alice and Bob's machines to set up the experiment environment.
2. **Compile the code on Alice and Bob's machines**
   
   Follow the compilation instructions to compile the source code on both machines.
3. **Run the experiment on Alice and Bob**
   
   Bob (Listener) IP: `10.9.130.72`  
   - **Using a predefined signal file**：
    ```bash
    sudo ./ping_program 10.9.130.122 100 1000 1 setup/signals/signal1.txt B --listen
    ```
    - **Using an MLS-generated signal (alternative to the above)**：
    ```bash
    sudo ./ping_program 10.9.130.122 1023 1000 2 n10s12 B --listen
    ```
    Alice (Active Prober) IP: `10.9.130.122`
    - **Using a predefined signal file**：
    ```bash
    sudo ./ping_program 10.9.130.72 100 1000 1 setup/signals/signal1.txt A --active
    ```
    - **Using an MLS-generated signal (alternative to the above)**：
    ```bash
    sudo ./ping_program 10.9.130.72 1023 1000 2 n10s12 A --active
    ```
4. **Data Collection**
   
   The experiment results will be stored in the `/data` directory. Each experiment dataset is saved in a folder named in the format: `{experiment_sequence}_{packet_count}_{signal_file}_{probe_frequency}_{host_label}` 
5. **Frequency Analysis & Key Generation**
   
   The collected RTT measurements will be used for frequency domain analysis to extract spectral features and perform key generation.

# License
This project is licensed under the MIT License - see the [LICENSE.txt](https://github.com/PaperplaneSun/NetProbe/blob/main/LICENSE) file for details