# Network analyzer
## Project's summary
The project aims at building a multiplatform application capable of intercepting incoming and outgoing traffic through the network interfaces of a computer. The application will set the network adapter in promiscuous mode, collect IP address, port and protocol type of observed traffic and will generate a textual report describing a synthesis of the observed events.
Such a report should list for each of the network address/port pairs that have been observed, the protocols that was transported, the cumulated number of bytes transmitted, the timestamp of the first and last occurrence of information exchange.
Command line parameters will be used to specify the network adapter to be inspected, the output file to be generated, the interval after which a new report is to be generated, or a possible filter to apply to captured data.

## Packet sniffer app
The packet sniffer app is a sample application to demonstrate the usage of the packet sniffer library.<br >
To get the possible commands run: <br>
`cargo run help`<br>
To run the capture:<br>
`cargo capture <DEVICE_NAME> <FILENAME> <INTERVAL> [FILTER]`<br>
where the file will be saved in "txt" format.
While running you can use the following commands:<br>
* `pause` to pause temporarily pause the capture<br>
* `resume` to resume the capture
* `stop` to interrupt the capture, it makes the program end


## Packet sniffer Library
The packet sniffer library is a cross platform library that allows the capture and recording of network traffic, aggregating it with respect to address/port pairs. Full library documentation is available through<br> `cargo doc --document-private-items --open
`

