from optparse import OptionParser

class v6Sig:
    def __init__(self,sigFile):
        self.sigFile = sigFile
        self.routerLifetime = 0
        self.naLimit = 0
        self.nsLimit = 0
        self.raLimit = 0
        
        config = ConfigParser.RawConfigParser(allow_no_value=True)
        #Define MAC of Router 
        self.trueRouter = ""
    

    def parseSig(self):
        sg = open(self.sigfile,"r")
        sign = sg.read()
        self.config.readfp(io.BytesIO(sign))



    
