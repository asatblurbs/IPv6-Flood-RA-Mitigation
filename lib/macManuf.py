
class macManuf:
    def __init__(self,manufile):
        self.macDict = {}
        manuf = open("data/"+manufile,"r")
        for line in manuf.readlines():
            line = line.strip()
            line_ = line.split("\t")
            co = line_[1]
            if "#" in line_[1]:
                co = line_[1].split("#")[1]     
            self.macDict[line_[0].lower()] = co.strip(" ")

    def getManuf(self,mac):
        if mac[:8] in self.macDict.keys():
            return self.macDict[mac[:8]]
        else:
            return "Unknow"


