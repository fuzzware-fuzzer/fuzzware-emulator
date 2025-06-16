from .. import globs

class CommunicatorInterface():
    def get_bytes(self, n=1):
        """
        Receive data from the communication channel.

        :param n:   Number of bytes required.
        """
        return n*b"\0"

    def has_bytes(self, n=1):
        """
        Check for data availability.
        :param n:   Number of bytes required.
        :return:    True, if n bytes are available for reading. False otherwise.
        """
        return True

    def put_bytes(self, bytestr):
        """
        Send data to the receiving end of the communication channel.
        :param bytestr:     The value to write.
        """
        pass

class FuzzwareCommunicator(CommunicatorInterface):
    def get_bytes(self, n=1):
        # Fuzzware reads data from fuzzing input as pseudo communication.
        from ..native import get_fuzz
        return get_fuzz(globs.uc, n)

    def has_bytes(self, n=1):
        from ..native import fuzz_remaining
        return n <= fuzz_remaining()

    def put_bytes(self, bytestr):
        # Fuzzware currently ignores outgoing communication.
        pass
