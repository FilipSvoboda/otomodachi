# Otomodachi

[![License](https://img.shields.io/badge/license-LGPL-blue.svg)](LICENSE)

Otomodachi is a Python library for communication with Omron PLCs using the HTTP/HTTPS protocol, which is also utilized by Sysmac Studio and NA displays. The implementation of the protocol is based on reverse engineering, observation, and experimentation.

## Installation

The library can be run either on Windows, where Sysmac Studio is already installed, or on other platforms. However, if you choose to run it on a different platform, you will need to transfer PLC login credentials and encryption keys. PLC login credentials and encryption keys are not included directly in the library for legal reasons.

To install the library on Windows:

1. Make sure that Sysmac Studio (tested on version 1.52) is installed on your system.
2. Use pip to install the library:

```
pip install otomodachi
```

To install the library on other platforms:

1. Install the library on a Windows system along with Sysmac Studio, following the same steps as you would on a Windows platform.

2. Export the login credentials by running the following command in the command prompt or terminal:

```
py -m otomodachi --export-credentials --file C:/Users/Filip/Desktop/credentials.py
```

This command will generate a file named "credentials.py" containing the exported login credentials (in plain text).

3. Transfer the "credentials.py" file to the target platform where you intend to run the library.

4. Install the library on the target platform using pip:

```
pip install otomodachi
```

5. Make sure that the "credentials.py" file is located in the same directory as your Python script that uses the Otomodachi library.


## Usage

```python
import otomodachi

# Create a connection to the PLC (older firmware)
plc = otomodachi.NexPLC("192.168.250.1")

# Create a connection to the PLC (firmware version >=1.6 ??)
plc = otomodachi.NexPLC("192.168.250.1", encrypted=True)

# Create a connection using credentials.py file
import credentials
plc = otomodachi.NexPLC("192.168.250.1", encrypted=True, credentials=credentials)

plc.CPU_getModel()
'NX1P2-9B24DT1'

plc.CPU_getPLCName()
'new_Controller_0'

plc.CPU_setPLCName('newname')

plc.CPU_getUnitVersion()
'1.60.01'

plc.CPU_getStatus()
['RUN', 'NoError']

plc.CPU_getStatusExtended()
'1 user=,vendor= ECAT=0,BuiltInIO=0,NXBus=0 0000'

plc.CPU_getTaskList()
'1 BaseTask,Base,4000000'

plc.CPU_getMode()
'RUN'

plc.CPU_setMode('program')

plc.CPU_setMode('run')

plc.CPU_getTotalPowerOnTime()
'CPU 72613'

plc.HTTP_getMaxRequestSize()
31457280

```

For more detailed usage instructions and examples, please refer to the [documentation](https://link-to-documentation).

## Proxy

The Proxy module is used to monitor the communication between a PLC and Sysmac Studio. The Proxy listens on a local IP address, allowing connections from Sysmac Studio. All requests made through the Proxy are forwarded to the physical PLC while logging both the requests and responses.

To start the Proxy, use the following example:

```python
import otomodachi
plc = otomodachi.NexPLC('192.168.250.1', encrypted=True)
otomodachi.proxy('0.0.0.0', 443, plc)
```

After starting the Proxy, you can connect to it using Sysmac Studio by specifying the address `127.0.0.1`. Please note that for successful connection, it is important that no other program on your local computer is listening on ports 80 or 443.


## Contributing

Contributions are welcome! If you find any issues or have suggestions for improvements, please open an issue or submit a pull request.

## License

This project is licensed under the [LGPL License](LICENSE).

## Contact

For questions or feedback, feel free to reach out to the project maintainer:

Filip Svoboda - filip.svoboda@gmail.com

## References

- [Omron PLC Documentation](https://link-to-omron-plc-docs)
- [Additional Resource 1](https://link-to-resource-1)
- [Additional Resource 2](https://link-to-resource-2)

## Project Status

Currently, the library is under development, and the API may change.

