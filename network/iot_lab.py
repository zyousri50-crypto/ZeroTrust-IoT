
from mininet.net import Mininet
from mininet.node import OVSSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel

SWITCH = "s1"
SERVER_IP = "10.0.0.100"

DEVICES = {
    "camera": "10.0.0.11",
    "sensor": "10.0.0.12"
}


def add_flow(switch, rule):
    result = switch.cmd(
        "ovs-ofctl -O OpenFlow13 add-flow "
        + SWITCH + " '" + rule + "'"
    )

    if result.strip():
        raise RuntimeError(result.strip())


def create_network():
    net = Mininet(
        controller=None,
        switch=OVSSwitch
    )

    try:
        camera = net.addHost(
            "camera", ip="10.0.0.11/24"
        )
        sensor = net.addHost(
            "sensor", ip="10.0.0.12/24"
        )
        server = net.addHost(
            "server", ip="10.0.0.100/24"
        )

        s1 = net.addSwitch(
            SWITCH,
            failMode="secure",
            protocols="OpenFlow13"
        )

        for host in (camera, sensor, server):
            net.addLink(host, s1)

        print("Starting IoT Network...")
        net.start()

        result = s1.cmd(
            "ovs-ofctl -O OpenFlow13 del-flows s1"
        )
        if result.strip():
            raise RuntimeError(result.strip())

        # Allow ARP for address resolution
        add_flow(
            s1,
            "priority=100,arp,actions=normal"
        )

        # Allow ICMP between authorized devices and server
        for device_ip in DEVICES.values():
            add_flow(
                s1,
                "priority=200,icmp,"
                "nw_src=" + device_ip + ","
                "nw_dst=" + SERVER_IP + ","
                "actions=normal"
            )

            add_flow(
                s1,
                "priority=200,icmp,"
                "nw_src=" + SERVER_IP + ","
                "nw_dst=" + device_ip + ","
                "actions=normal"
            )

        # Default deny for all other traffic
        add_flow(
            s1,
            "priority=0,actions=drop"
        )

        print("Security rules added!")
        print("Network is ready!")

        CLI(net)

    finally:
        net.stop()


if __name__ == "__main__":
    setLogLevel("info")
    create_network()
