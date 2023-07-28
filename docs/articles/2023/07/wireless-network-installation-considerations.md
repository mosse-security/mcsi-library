:orphan:
(wireless-network-installation-considerations)=

# Wireless Network Installation Considerations

Wireless network installation requires careful planning and consideration to ensure optimal performance, coverage, and security. 

Wireless Access Point (WAP) Placement: Wireless Access Point (WAP) placement refers to the strategic positioning of wireless access points within a network to ensure optimal coverage and performance. A wireless access point is a network device that allows wireless-capable devices, such as laptops, smartphones, and tablets, to connect to a wired network using Wi-Fi technology. Proper WAP placement is critical to providing reliable and high-quality wireless connectivity to users within the coverage area.

## What is an Access Point (AP)?

An Access Point (AP) is a hardware device that enables wireless devices to connect to a wired network. It acts as a bridge between wireless devices and the wired infrastructure, allowing wireless devices to communicate with other devices and access network resources. An access point usually has antennas to transmit and receive wireless signals and provides wireless connectivity within its coverage range.

## SSID (Service Set Identifier)

SSID stands for Service Set Identifier. It is the name of a wireless network that allows wireless devices to identify and connect to the correct network. When you search for available Wi-Fi networks on your device, you'll see a list of SSIDs. Each SSID represents a different wireless network that you can connect to.

When setting up a wireless network, you need to choose an SSID for your network. Users who want to connect to your Wi-Fi network will select your SSID from the list and enter the appropriate security credentials (such as a password) to establish the connection.

It's important to note that SSIDs are essential for network security, but they are not a security measure themselves. Even if you hide the SSID (a setting called "SSID broadcast disabled"), determined attackers can still find the hidden network. Therefore, using strong security measures like encryption (WPA2/WPA3) and strong passwords is crucial to protect your wireless network from unauthorized access.

Wireless networks can operate in either the 2.4 GHz or 5 GHz radio band. For performance reasons, the channels chosen should be as widely spaced as possible to reduce different types of interference:

**1. Co-channel interference (CCI):** Co-channel interference occurs when two or more wireless access points (APs) or routers use the same wireless channel to communicate. In a Wi-Fi network, channels are used to divide the available frequency spectrum to allow multiple devices to operate simultaneously without significant interference. However, if neighboring access points use the same channel, they can interfere with each other's signals.

When CCI happens, the performance and throughput of affected wireless devices can degrade, leading to slower data rates, increased latency, and a decrease in overall network efficiency. This is especially problematic in high-density areas with many Wi-Fi networks competing for the same channels.

To mitigate co-channel interference, network administrators should carefully plan their wireless deployments, strategically selecting non-overlapping channels (e.g., channels 1, 6, and 11 in the 2.4 GHz band) and optimizing the placement of access points to minimize signal overlap.

**2. Adjacent channel interference (ACI):** Adjacent channel interference occurs when two wireless devices or networks use channels that are adjacent to each other. In this situation, the signals from one channel can "spill over" into the adjacent channels, causing interference and degrading performance.

For example, in a Wi-Fi network operating on the 5 GHz band, adjacent channels have a significant overlap. If two access points use channels that are next to each other, the signals from each AP can interfere with neighbouring channels, leading to decreased performance and data throughput for devices using those channels.

To avoid adjacent channel interference, it's crucial to ensure that adjacent access points or wireless networks are using non-overlapping channels or, if possible, channels with the maximum separation to minimize interference.

## Identification of overlapping

A site survey is a critical process used to assess and analyse the wireless signal strength, channel usage, and overall RF environment throughout the area where wireless coverage is required. The goal of the site survey is to gather data and insights that help design and deploy an efficient and reliable wireless network. Before conducting the site survey, the wireless network administrator defines the objectives of the survey, such as the desired coverage area, user density, and specific applications that the network will support. They also gather floor plans and information about potential obstacles or sources of interference. 

The administrator selects appropriate survey tools, which can be hardware-based or software-based. These tools typically include Wi-Fi spectrum analysers, Wi-Fi scanners, and mapping software to visualize the collected data. The surveyor walks or moves through the target area, systematically recording signal strength readings at various locations. These measurements are typically presented as signal-to-noise ratio (SNR) values or received signal strength indicator (RSSI) values. This data helps identify areas with strong coverage, weak coverage (dead spots), and potential sources of interference. 

The surveyor examines the existing wireless channels in use by nearby access points and neighbouring networks. This step helps identify potential channel overlap or congestion, which can lead to co-channel interference or adjacent channel interference. The collected data is then used to create heat maps. 

Heat maps are graphical representations of signal strength and coverage areas. They help visualize the strength and quality of the wireless signal across the survey area, making it easier to identify areas with poor coverage or interference. This information helps in making adjustments to channel selection and power settings to minimize interference. 

Based on the data and insights from the site survey, the network administrator can design an optimal network deployment plan. This may involve adjusting the placement of access points, selecting appropriate channels, and configuring power settings to achieve the desired coverage and performance. After the site survey, the collected data is carefully analysed, and adjustments are made to the network design if necessary. It's common to conduct multiple site surveys and iterations to fine-tune the network for optimal performance.