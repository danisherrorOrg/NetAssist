import time
from collections import deque


class PacketCounter:

    def __init__(self):
        self.packet_times = deque()

    def record_packet(self):
        """
        Record packet arrival time
        """
        now = time.time()
        self.packet_times.append(now)

        # Remove packets older than 1 second
        while self.packet_times and now - self.packet_times[0] > 1:
            self.packet_times.popleft()

    def packets_per_second(self):
        """
        Return packets captured in last 1 second
        """
        return len(self.packet_times)