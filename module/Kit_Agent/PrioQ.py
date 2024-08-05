class PrioQ:
    def __init__(self):
        self.store = list()
    # Take [ts, host] items    
    def add(self,item): 
        if not self.full(): 
            self.store.append(item)
        else: 
            for i in self.store:
                # Added items will have newer timestamps, 
                #   so should update that timestamp
                if item[1] == i[1]:
                    i[0] == item[0]
                    self.store.sort()
                    return
            # Greater ts -> newer packet. 
            if item[0] > self.store[0][0]: 
                self.store[0] = item
        self.store.sort()
    def more_recent(self,ts):
        rec = list()
        for i in self.store: 
            if i[0] >= ts - 5: 
                rec.append(i[1])
        rec.reverse()
        return rec
    def empty(self): 
        return len(self.store) == 0
    def full(self):
        return len(self.store) == 3
    def __str__(self) -> str:
        return str(self.store)

p = PrioQ()
p.add([1,"1"])
print(p)
p.add([3,"2"])
print(p)

p.add([5,"3"])
print(p)

p.add([4,"4"])
print(p)

p.add([4,"1"])
print(p)

p.add([6,"6"])
print(p)

print(p.more_recent(10))