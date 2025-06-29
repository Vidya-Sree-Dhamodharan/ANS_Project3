from mininet.net import Containernet
from mininet.node import RemoteController, OVSSwitch
from mininet.cli import CLI
from mininet.link import TCLink
from mininet.log import setLogLevel, info

def run():
    setLogLevel('info')
    net = Containernet(controller=None, switch=OVSSwitch, link=TCLink)

    info('*** Adding controllers:\n')
    c1 = net.addController('c1', controller=RemoteController, ip='127.0.0.1', port=6655)
    info('c1\n')

    info('*** Adding switches:\n')
    s1 = net.addSwitch('s1')
    info('s1\n')

    info('*** Adding hosts:\n')
    h1 = net.addHost('h1')
    h2 = net.addHost('h2')
    h3 = net.addHost('h3')
    h4 = net.addHost('h4')
    info('h1 h2 h3 h4\n')

    info('*** Adding links:\n')
    info('(h1, s1) (h2, s1) (h3, s1) (h4, s1)\n')
    net.addLink(h1, s1)
    net.addLink(h2, s1)
    net.addLink(h3, s1)
    net.addLink(h4, s1)

    info('*** Building and starting network\n')
    net.build()
    c1.start()

    info('*** Starting switch:\n')
    s1.start([c1])
    info('s1\n')

    info('*** Running CLI:\n')
    CLI(net)

    info('*** Stopping network\n')
    net.stop()

if __name__ == '__main__':
    run()