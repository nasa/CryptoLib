from enum import Enum
from random import randrange, choice

class KeyStates(Enum):
    KEY_PREACTIVE   = 1
    KEY_ACTIVE      = 2
    KEY_DEACTIVATED = 3
    KEY_DESTROYED   = 4
    KEY_CORRUPTED   = 5


class New_Key:
    def __init__(self, key:str = "", state:int = 0, index:int = 0, random:bool = False, rand_length:int = 0):
        self.key = key
        self.state = state
        self.index = index
        self.length = 0
        self.rand_length = rand_length
        self.key_bytes = []
    
        i = 0
        if not random:
            while(i < (len(self.key)-1)):
                self.key_bytes.append("0x" + self.key[i] + self.key[i+1])
                i += 2
            self.length = len(self.key_bytes)
        else:
            self._do_random()

    def _do_random(self):
        i = 0
        if not self.index:
            self.index = randrange(0,256,1)
        if not self.state:
            self.state = randrange(1,5,1)
        if not self.rand_length:
            self.length = choice([16, 32, 64])
        else:
            self.length = self.rand_length
        while(i<self.length):
            value = randrange(0,255,1)
            if value < 16:
                self.key_bytes.append(("0x0" + hex(value).split('x')[1]))
            else:
                self.key_bytes.append(hex(value))
            self.key += self.key_bytes[i].split('x')[1]
            i += 1

    def print_keyring_entry(self):
        print(f'// {self.index} - {self.key}')
        for i in range(self.length):
            print(f'key_ring[{self.index}].value[{i}] = {self.key_bytes[i]};')
        print(f'key_ring[{self.index}].key_len = {self.length};')
        print(f'key_ring[{self.index}].key_state = {KeyStates(self.state).name};\n')

    def get_len(self):
        return self.length

    def get_state(self):
        return self.state



if __name__ == '__main__':
    # Key Example
        # 1:
    something = New_Key(key="101112131415161718191A1B1C1D1E1F101112131415161718191A1B1C1D1E1F", state=KeyStates.KEY_ACTIVE, index=69)
    something.print_keyring_entry()

        # 2:
    something = New_Key(index=12, state=KeyStates.KEY_ACTIVE, random=True, rand_length=13)
    something.print_keyring_entry()

        # 3:
    something = New_Key(random=True)
    something.print_keyring_entry()