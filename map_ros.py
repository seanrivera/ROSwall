import xmlrpc.client as rpcclient
import itertools
from multiprocessing import Pool, Event


class Result():
    '''
    Results are objects
    '''

    def __init__(self, last_event=0):
        self.last_event = last_event
        self.signal_flag = Event()
        self.ip_addr = ""
        self.port = 0
        self.ros_name = ""

    def check_node(self):
        '''
        Checks if a node is still at the last known location.
        :return: True if it is, false otherwise.
        '''
        with rpcclient.ServerProxy(self.ip_addr + ":" + str(self.port)) as proxy:
            (code, status, bus_info) = proxy.getBusInfo("/ROSDN")
        # TODO: Make sure that you get the right parameter
        if bus_info[0] == self.ros_name:
            return True
        return False

    def update_node(self, ip_addr, port, event_counter):
        '''
        Update the node that this result object is pointing two
        :param ip_addr: New IP address to point to
        :param port:  New port to point to
        :param event_counter:  THe current global event counter.
        :return: True if the node has been updated false otherwise.
        '''
        # It's updating elsewhere
        if self.signal_flag.is_set():
            return False
        self.signal_flag.set()
        # We haven't had a cache miss and shouldn't update
        if self.last_event >= event_counter():
            return False
        self.last_event = event_counter
        self.ip_addr = ip_addr
        self.port = port
        with rpcclient.ServerProxy(self.ip_addr + ":" + str(self.port)) as proxy:
            (code, status, bus_info) = proxy.getBusInfo("/ROSDN")
        self.ros_name = bus_info[0]


class ROSStateMapper():
    def __init__(self, pool_size=10):
        self.state_list = {}
        self.master_uri = ''
        self.master_port = ''
        # Updated Counter is incremented everytime there is a master miss. Nodes in the state machine with a last updated
        # less then update counter need to be updated gain
        self.update_counter = 0
        self.thread_pool = Pool(processes=pool_size)

    def update_state(self):
        '''
        This function updates the internal state graph. It gets a list of nodes, topics, and services from the master
        then it goes through and verifies each one is correct by connecting to the claimed port
        :return: none
        '''
        proxy = rpcclient.ServerProxy(self.master_uri)
        # TODO: Make sure to whitelist the connection
        code, statusMessage, system_state = proxy.getSystemState('/ROSDN')
        publisher_list = system_state[0]
        subscriber_list = system_state[1]
        service_list = system_state[2]
        node_set = set()
        topic_set = set()
        # Publisher has the syntax of [topic, [publisher1, publisher2, publisher3]]
        # Subscriber has the synax of [topic, [subscriber1, subscriber2, subscriber3]]
        for (publisher, subscriber) in itertools.zip_longest(publisher_list, subscriber_list):
            topic_set.add(publisher[0])
            node_set.update(publisher[1])
            topic_set.add(subscriber[0])
            node_set.update(subscriber[1])

        # TODO validate each node.
        for node in node_set:
            print(node)
