# pka2xml

A tool for working with Cisco Packet Tracer files.

## Features

- Decrypt pka/pkt files to xml
- Encrypt xml files to pka/pkt
- Modify user profile names in pka/pkt files
- Batch process multiple files
- Create multiple variations of a file with different names

## Building

Choose the appropriate build script for your platform:

### macOS
```bash
./build-macos.sh
```
This will:
- Check for and install required dependencies via Homebrew
- Build the project
- Provide instructions for optional system-wide installation

### Linux
```bash
./build-linux.sh
```
This will:
- Detect your package manager (apt, dnf, yum, or pacman)
- Install required dependencies
- Build the project
- Provide instructions for optional system-wide installation

### Docker
```bash
./build-docker.sh
```
This will:
- Build the Docker image
- Run the container with the tool installed

## Usage

```bash
pka2xml [options]

Options:
  -d <in> <out>   Decrypt pka/pkt to xml
  -e <in> <out>   Encrypt xml to pka/pkt
  -f <in> <out>   Allow packet tracer file to be read by any version
  -nets <in>      Decrypt packet tracer "nets" file
  -logs <in>      Decrypt packet tracer log file
  -r <in> <name>  Modify user profile name in pka/pkt file (creates new file)
  -rb <name> <files...>  Batch modify user profile name in multiple pka/pkt files
  -rbm <in> <names...>  Create multiple variations of a file with different names
  --forge <out>   Forge authentication file to bypass login
  -v              Verbose output

Examples:
  pka2xml -d foobar.pka foobar.xml
  pka2xml -e foobar.xml foobar.pka
  pka2xml -nets $HOME/packettracer/nets
  pka2xml -logs $HOME/packettracer/pt_12.05.2020_21.07.17.338.log
  pka2xml -r file.pka "New Name"  # Creates file_NewName.pka
  pka2xml -rb "New Name" file1.pka file2.pka file3.pka  # Creates file1_NewName.pka, etc.
  pka2xml -rbm file.pka "Name1" "Name2" "Name3"  # Creates file_Name1.pka, file_Name2.pka, etc.
```

## Uninstallation

### macOS
```bash
sudo make uninstall-macos
```

### Linux
```bash
sudo make uninstall
```

### Docker
```bash
docker rmi pka2xml:1.0.0
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.